#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/udp.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/atomic.h>
#include <linux/netlink.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/ratelimit.h>

MODULE_AUTHOR("1day");
MODULE_DESCRIPTION("Kernel firewall");
MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: netfilter");



// ############################## DEFENITIONS ##############################

#define MAX_RULES 100
#define MAX_BUFFER_SIZE 128
#define MAX_WHITELIST 64
#define NETLINK_USER 31
#define NETLINK_LOG 30
#define ACCEPT_LOG_RATE_LIMIT 20
#define MAX_IPS_PER_REQUEST 10

static struct sock *nl_sk = NULL;
unsigned short WEB_PORT = 9876;
unsigned short NODE_APP_PORT = 9877;
static DEFINE_SPINLOCK(rule_lock);
static struct fw_config fw_config;
static int rule_count = 0;
static bool stealth_mode = false;
static bool lockdown_mode = false;
struct sock *netlink_log_sock;
static atomic_t accept_log_counter = ATOMIC_INIT(0);

struct fw_config {
    struct list_head whitelist;
    spinlock_t whitelist_lock;
    int whitelist_count;
};

typedef enum {
    DIRECTION_INCOMING = 1,
    DIRECTION_OUTGOING = 0
} direction_t;

typedef enum {
    ACTION_ALLOW = 1,
    ACTION_DENY = 0
} action_t;

typedef enum {
    PROTOCOL_ALL = IPPROTO_IP,      // 0 - Matches kernel's IPPROTO_IP
    PROTOCOL_ICMP = IPPROTO_ICMP,   // 1
    PROTOCOL_IGMP = IPPROTO_IGMP,   // 2
    PROTOCOL_TCP = IPPROTO_TCP,     // 6
    PROTOCOL_UDP = IPPROTO_UDP,     // 17
    PROTOCOL_ICMPV6 = IPPROTO_ICMPV6, // 58
    PROTOCOL_OTHER = 255            // For any protocol not explicitly listed
} protocol_t;

struct whitelist_entry {
    __be32 ip;
    struct list_head list;
};

typedef struct __attribute__((packed)) {
    __u64 timestamp_ns;
    __be32 src_ip;
    __be32 dest_ip;
    __be16 src_port;
    __be16 dest_port;
    protocol_t protocol;
    __u32 packet_len;
    action_t action;
    char reason[32];
    char direction[16];
    int rule_id;
} packet_log_t;

typedef struct __attribute__((packed)) {
    int id;
    action_t action;
    direction_t direction;
    protocol_t protocol;
    __be16 port;
    __be32 ip;
} firewall_rule_t;

static firewall_rule_t rules[MAX_RULES];



// ############################## FUNCTION DECLARATIONS ##############################

void netlink_send(int pid, const char *fmt, ...);
void netlink_log(const packet_log_t *log);
packet_log_t *create_log_entry(struct sk_buff *skb, action_t action, const char *reason,
                              direction_t direction, int rule_id);
firewall_rule_t *parse_rule(const char *cmd);
static bool add_whitelist_ip(__be32 ip);
static bool remove_whitelist_ip(__be32 ip);
static int process_multi_whitelist_add(int pid, char *ips_str);
static bool delete_rule(int rule_id);
static void flush_arp_cache(void);
static bool is_whitelisted(__be32 ip);
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static unsigned int lockdown_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void netlink_recv(struct sk_buff *skb);
static void netlink_log_recv(struct sk_buff *skb);

// ############################## NETLINK FUNCTIONS ##############################

void netlink_send(int pid, const char *fmt, ...) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    char *msg_buf;
    int msg_size;
    int res;
    va_list args;

    if (!fmt) {
        pr_err("Null format string\n");
        return;
    }

    if (!nl_sk) {
        pr_err("Netlink socket is NULL\n");
        return;
    }

    msg_buf = kmalloc(NLMSG_GOODSIZE, GFP_KERNEL);
    if (!msg_buf) {
        pr_err("Failed to allocate message buffer\n");
        return;
    }

    va_start(args, fmt);
    msg_size = vsnprintf(msg_buf, NLMSG_GOODSIZE, fmt, args);
    va_end(args);

    if (msg_size < 0) {
        pr_err("Message formatting failed\n");
        kfree(msg_buf);
        return;
    }

    skb_out = nlmsg_new(msg_size + 1, in_atomic() ? GFP_ATOMIC : GFP_KERNEL);
    if (!skb_out) {
        pr_err("Failed to allocate skb\n");
        kfree(msg_buf);
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size + 1, 0);
    if (!nlh) {
        pr_err("Failed to create Netlink message header\n");
        kfree_skb(skb_out);
        kfree(msg_buf);
        return;
    }

    memcpy(nlmsg_data(nlh), msg_buf, msg_size + 1);
    kfree(msg_buf);

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0) {
        pr_err_ratelimited("Netlink send failed: %d (PID %d)\n", res, pid);
    }
}

// ############################## LOGGING FUNCTIONS ##############################

packet_log_t *create_log_entry(struct sk_buff *skb, action_t action, const char *reason,
                              direction_t direction, int rule_id) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    packet_log_t *log_entry;
    struct timespec64 ts;

    log_entry = kzalloc(sizeof(packet_log_t), GFP_ATOMIC);
    if (!log_entry)
        return NULL;

    ktime_get_real_ts64(&ts);
    log_entry->timestamp_ns = timespec64_to_ns(&ts);
    log_entry->rule_id = rule_id;

    if (!skb) {
        snprintf(log_entry->reason, sizeof(log_entry->reason), "No skb");
        return log_entry;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header) {
        snprintf(log_entry->reason, sizeof(log_entry->reason), "No IP header");
        return log_entry;
    }

    log_entry->src_ip = ip_header->saddr;
    log_entry->dest_ip = ip_header->daddr;
    log_entry->packet_len = skb->len;
    log_entry->action = action;

    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            if (pskb_may_pull(skb, ip_header->ihl * 4 + sizeof(struct tcphdr))) {
                tcp_header = (struct tcphdr *)(skb_network_header(skb) + ip_header->ihl * 4);
                log_entry->src_port = ntohs(tcp_header->source);
                log_entry->dest_port = ntohs(tcp_header->dest);
                log_entry->protocol = PROTOCOL_TCP;
            }
            break;
            
        case IPPROTO_UDP:
            if (pskb_may_pull(skb, ip_header->ihl * 4 + sizeof(struct udphdr))) {
                udp_header = (struct udphdr *)(skb_network_header(skb) + ip_header->ihl * 4);
                log_entry->src_port = ntohs(udp_header->source);
                log_entry->dest_port = ntohs(udp_header->dest);
                log_entry->protocol = PROTOCOL_UDP;
            }
            break;
            
        case IPPROTO_ICMP:
            log_entry->protocol = PROTOCOL_ICMP;
            break;
            
        default:
            log_entry->protocol = PROTOCOL_OTHER;
            break;
    }

    if (reason) {
        if (rule_id >= 0) {
            snprintf(log_entry->reason, sizeof(log_entry->reason), "%s : %d", reason, rule_id);
        } else {
            snprintf(log_entry->reason, sizeof(log_entry->reason), "%s", reason);
        }
    }

    return log_entry;
}

void netlink_log(const packet_log_t *log) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int res;

    if (!netlink_log_sock) {
        pr_debug_ratelimited("Netlink log socket not available");
        return;
    }

    skb_out = nlmsg_new(sizeof(*log), GFP_ATOMIC);
    if (!skb_out) {
        pr_debug_ratelimited("Failed to allocate skb for log");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, sizeof(*log), 0);
    if (!nlh) {
        pr_debug_ratelimited("Failed to create nlmsg header");
        kfree_skb(skb_out);
        return;
    }

    memcpy(nlmsg_data(nlh), log, sizeof(*log));

    res = nlmsg_multicast(netlink_log_sock, skb_out, 0, 1, GFP_ATOMIC);
    if (res < 0 && res != -3) {
        pr_debug_ratelimited("Netlink multicast failed: %d", res);
    }
}

static void log_packet(struct sk_buff *skb, action_t action, const char *reason,
                      direction_t direction, int rule_id) {
    if (action == ACTION_ALLOW && rule_id == -1) {
        if (atomic_inc_return(&accept_log_counter) % ACCEPT_LOG_RATE_LIMIT != 0) {
            return;
        }
    }

    packet_log_t *log_entry = create_log_entry(skb, action, reason, direction, rule_id);
    if (log_entry) {
        netlink_log(log_entry);
        kfree(log_entry);
    }
}

// ############################## FIREWALL CORE FUNCTIONS ##############################

firewall_rule_t *parse_rule(const char *cmd) {
    firewall_rule_t *rule;
    char *tmp, *orig_tmp, *token;
    int temp_value;

    rule = kmalloc(sizeof(firewall_rule_t), GFP_KERNEL);
    if (!rule)
        return NULL;

    orig_tmp = kstrdup(cmd, GFP_KERNEL);
    if (!orig_tmp) {
        kfree(rule);
        return NULL;
    }

    tmp = orig_tmp;

    token = strsep(&tmp, ";"); // Command type
    if (!token) goto error;

    token = strsep(&tmp, ";"); // Rule ID
    if (!token || kstrtoint(token, 10, &rule->id)) goto error;
    if (!(rule->id > 0)) goto error;

    token = strsep(&tmp, ";"); // Action
    if (!token || kstrtoint(token, 10, &temp_value)) goto error;
    rule->action = (action_t) temp_value;

    token = strsep(&tmp, ";"); // Direction
    if (!token || kstrtoint(token, 10, &temp_value)) goto error;
    rule->direction = (direction_t) temp_value;

    token = strsep(&tmp, ";"); // Protocol
    if (!token) goto error;
    if (strcmp(token, "tcp") == 0) {
        rule->protocol = PROTOCOL_TCP;
    } else if (strcmp(token, "udp") == 0) {
        rule->protocol = PROTOCOL_UDP;
    } else if (strcmp(token, "icmp") == 0) {
        rule->protocol = PROTOCOL_ICMP;
    } else if (strcmp(token, "all") == 0) {
        rule->protocol = PROTOCOL_ALL;
    } else {
        pr_err("Invalid protocol: %s\n", token);
        goto error;
    }

    token = strsep(&tmp, ";"); // Port
    if (!token || kstrtoint(token, 10, &temp_value)) goto error;
    if (temp_value < 0 || temp_value > 65535) goto error;
    rule->port = (__be16) htons((__u16)temp_value);

    token = strsep(&tmp, ";"); // IP Address
    if (!token) goto error;
    if (strcmp(token, "0.0.0.0") == 0) {
        rule->ip = 0;
    } else if (!in4_pton(token, -1, (u8 *)&rule->ip, -1, NULL)) {
        pr_err("Invalid IP address: %s\n", token);
        goto error;
    }

    kfree(orig_tmp);
    return rule;

error:
    kfree(orig_tmp);
    kfree(rule);
    return NULL;
}


// Helper function to flush the arp cache using a system command
static void flush_arp_cache(void) {
    static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
        NULL
    };

    static char *argv[] = {
        "/bin/bash",
        "-c",
        "ip neigh flush all",
        NULL
    };

    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);

    if (ret != 0) {
        pr_err("Failed to flush ARP cache. ret=%d\n", ret);
    }
}


// Function to delete a rule using the `rule_id`
static bool delete_rule(int rule_id) {
    bool found = false;
    spin_lock(&rule_lock);
    
    for (int i = 0; i < rule_count; i++) {
        if (rules[i].id == rule_id) {
            found = true;
            for (int j = i; j < rule_count - 1; j++) {
                rules[j] = rules[j + 1];
            }
            rule_count--;
            break;
        }
    }

    spin_unlock(&rule_lock);
    return found;
}





// ############################## WHITELIST FUNCTIONS ##############################

static bool add_whitelist_ip(__be32 ip) {
    struct whitelist_entry *entry;
    bool exists = false;

    spin_lock(&fw_config.whitelist_lock);
    
    list_for_each_entry(entry, &fw_config.whitelist, list) {
        if (entry->ip == ip) {
            exists = true;
            break;
        }
    }

    if (!exists && fw_config.whitelist_count < MAX_WHITELIST) {
        entry = kmalloc(sizeof(struct whitelist_entry), GFP_ATOMIC);
        if (!entry) {
            spin_unlock(&fw_config.whitelist_lock);
            return false;
        }
        entry->ip = ip;
        list_add_tail(&entry->list, &fw_config.whitelist);
        fw_config.whitelist_count++;
        exists = true;
    }

    spin_unlock(&fw_config.whitelist_lock);
    return exists;
}

static bool remove_whitelist_ip(__be32 ip) {
    struct whitelist_entry *entry, *tmp;
    bool found = false;

    spin_lock(&fw_config.whitelist_lock);
    
    list_for_each_entry_safe(entry, tmp, &fw_config.whitelist, list) {
        if (entry->ip == ip) {
            list_del(&entry->list);
            kfree(entry);
            fw_config.whitelist_count--;
            found = true;
            break;
        }
    }

    spin_unlock(&fw_config.whitelist_lock);
    return found;
}

static int process_multi_whitelist_add(int pid, char *ips_str) {
    char *ip_token, *tmp;
    __be32 ip;
    int count = 0;
    char response[512] = {0};
    int response_len = 0;
    bool success;

    tmp = ips_str;
    while ((ip_token = strsep(&tmp, ","))) {
        if (!*ip_token)
            continue;

        if (count >= MAX_IPS_PER_REQUEST) {
            netlink_send(pid, "Maximum %d IPs per request exceeded", MAX_IPS_PER_REQUEST);
            return -EINVAL;
        }

        if (!in4_pton(ip_token, -1, (u8 *)&ip, -1, NULL)) {
            netlink_send(pid, "Invalid IP address: %s", ip_token);
            return -EINVAL;
        }

        success = add_whitelist_ip(ip);
        if (success) {
            response_len += snprintf(response + response_len, 
                                  sizeof(response) - response_len,
                                  "%pI4: added, ", &ip);
            count++;
        } else {
            response_len += snprintf(response + response_len, 
                                  sizeof(response) - response_len,
                                  "%pI4: failed (exists/limit), ", &ip);
        }
    }

    if (count > 0) {
        if (response_len >= 2) {
            response[response_len-2] = '\0';
        }
        netlink_send(pid, "%s", response);
    } else {
        netlink_send(pid, "No valid IPs processed");
    }

    return count;
}

static bool is_whitelisted(__be32 ip) {
    struct whitelist_entry *entry;
    bool found = false;
    
    spin_lock(&fw_config.whitelist_lock);
    list_for_each_entry(entry, &fw_config.whitelist, list) {
        if (entry->ip == ip) {
            found = true;
            break;
        }
    }
    spin_unlock(&fw_config.whitelist_lock);
    return found;
}




// ############################## NETFILTER HOOKS ##############################


// Hook for Lockdown mode
static unsigned int lockdown_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    static atomic_t log_counter = ATOMIC_INIT(0);
    static atomic_t initial_logs = ATOMIC_INIT(3);

    if (unlikely(lockdown_mode)) {
        struct iphdr *ip_header = ip_hdr(skb);

        if (ip_header && (ip_header->protocol == IPPROTO_TCP || ip_header->protocol == IPPROTO_UDP)) {
            void *transport_header = (void *)ip_header + ip_header->ihl * 4;

            __be16 src_port = 0, dst_port = 0;
            if (ip_header->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp_header = (struct tcphdr *)transport_header;
                src_port = ntohs(tcp_header->source);
                dst_port = ntohs(tcp_header->dest);
            } else if (ip_header->protocol == IPPROTO_UDP) {
                struct udphdr *udp_header = (struct udphdr *)transport_header;
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
            }

            if (src_port == WEB_PORT || dst_port == WEB_PORT || 
                src_port == NODE_APP_PORT || dst_port == NODE_APP_PORT) {
                return NF_ACCEPT;
            }
        }

        bool should_log = false;
        if (atomic_read(&initial_logs) > 0) {
            atomic_dec(&initial_logs);
            should_log = true;
        } else if (atomic_inc_return(&log_counter) % 20 == 0) {
            should_log = true;
        }

        if (should_log) {
            log_packet(skb, ACTION_DENY, "Lockdown mode",
                (state->hook == NF_INET_LOCAL_IN) ? DIRECTION_INCOMING : DIRECTION_OUTGOING,
                -1);
        }
        return NF_DROP;
    }

    return NF_ACCEPT;
}


// Main hook
static unsigned int firewall_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;
    __be32 pkt_ip; 
    __be16 pkt_port = 0; 
    protocol_t pkt_protocol = PROTOCOL_OTHER;
    direction_t direction;
    int i;
    bool matched = false;
    action_t final_action = ACTION_ALLOW;
    unsigned int verdict = NF_ACCEPT;
    const char *reason = "Default allow";
    int matched_rule_id = -1;
    bool is_tcp_syn = false;

    if (!skb || !state || !skb_network_header(skb)) {
        log_packet(skb, ACTION_DENY, "Invalid packet", DIRECTION_INCOMING, -1);
        return NF_ACCEPT;
    }

    if (skb->protocol != htons(ETH_P_IP)) {
        log_packet(skb, ACTION_ALLOW, "Non-IP packet", DIRECTION_INCOMING, -1);
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->version != 4) {
        log_packet(skb, ACTION_DENY, "Invalid IP version", DIRECTION_INCOMING, -1);
        return NF_ACCEPT;
    }

    direction = (state->hook == NF_INET_LOCAL_IN) ? DIRECTION_INCOMING : DIRECTION_OUTGOING;
    pkt_ip = (direction == DIRECTION_INCOMING) ? ip_header->saddr : ip_header->daddr;

    if (fw_config.whitelist_count > 0 && is_whitelisted(pkt_ip)) {
        log_packet(skb, ACTION_ALLOW, "Whitelisted IP", direction, -1);
        return NF_ACCEPT;
    }

    switch (ip_header->protocol) {
        case IPPROTO_TCP:
            pkt_protocol = PROTOCOL_TCP;
            if (pskb_may_pull(skb, ip_header->ihl * 4 + sizeof(struct tcphdr))) {
                tcp_header = (struct tcphdr *)(skb_network_header(skb) + ip_header->ihl * 4);
                pkt_port = ntohs(tcp_header->dest);
                is_tcp_syn = (tcp_header->syn && !tcp_header->ack);
            }
            break;
        
        case IPPROTO_UDP:
            pkt_protocol = PROTOCOL_UDP;
            if (pskb_may_pull(skb, ip_header->ihl * 4 + sizeof(struct udphdr))) {
                udp_header = (struct udphdr *)(skb_network_header(skb) + ip_header->ihl * 4);
                pkt_port = ntohs(udp_header->dest);
            }
            break;
        
        case IPPROTO_ICMP:
            pkt_protocol = PROTOCOL_ICMP;
            // Don't log ICMP rejections for blocked TCP/UDP packets
            if (direction == DIRECTION_INCOMING) {
                struct icmphdr *icmp_header;
                if (pskb_may_pull(skb, ip_header->ihl * 4 + sizeof(struct icmphdr))) {
                    icmp_header = (struct icmphdr *)(skb_network_header(skb) + ip_header->ihl * 4);
                    if (icmp_header->type == ICMP_DEST_UNREACH) {
                        return NF_ACCEPT;
                    }
                }
            }
            break;
            
        default:
            pkt_protocol = PROTOCOL_OTHER;
            break;
    }

    spin_lock(&rule_lock);
    for (i = 0; i < rule_count; i++) {
        firewall_rule_t *rule = &rules[i];
        
        if (rule->direction != direction) continue;
        if (rule->protocol != PROTOCOL_ALL && rule->protocol != pkt_protocol) continue;
        if (rule->ip != 0 && rule->ip != pkt_ip) continue;
        if (rule->port != 0 && rule->port != htons(pkt_port)) continue;
        
        matched = true;
        final_action = rule->action;
        matched_rule_id = rule->id;
        reason = final_action == ACTION_ALLOW ? "Rule allowed" : "Rule denied";
        break;
    }
    spin_unlock(&rule_lock);

    verdict = (matched && final_action == ACTION_DENY) ? NF_DROP : NF_ACCEPT;
    
    if (matched) {
        // Only log the original packet, not ICMP responses
        if (pkt_protocol != PROTOCOL_ICMP) {
            log_packet(skb, final_action, reason, direction, matched_rule_id);
        }
    } else if (!matched && pkt_protocol == PROTOCOL_TCP && is_tcp_syn && stealth_mode) {
        log_packet(skb, ACTION_DENY, "Stealth mode - SYN scan blocked", direction, -1);
    } else {
        log_packet(skb, ACTION_ALLOW, reason, direction, -1);
    }
    
    return verdict;
}



static struct nf_hook_ops firewall_ops[] = {
    {
        .hook = firewall_hook,
        .hooknum = NF_INET_LOCAL_IN,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = firewall_hook,
        .hooknum = NF_INET_LOCAL_OUT,
        .pf = PF_INET,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = lockdown_hook,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
    },
    {
        .hook = lockdown_hook,
        .hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_IPV6,
        .priority = NF_IP_PRI_FIRST,
    }
};



// ############################## NETLINK RECEIVE HANDLERS ##############################

static void netlink_log_recv(struct sk_buff *skb) {
    /* No action needed for log receiver */
}

static void netlink_recv(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    char *cmd = NULL, *token = NULL, *tmp = NULL;
    firewall_rule_t *rule = NULL;
    bool deleted;
    int rule_id = 0, pid = 0;
    bool is_update = false, is_delete = false, is_config = false, is_whitelist = false;
    __be32 ip;

    if (!skb) {
        pr_err("Received NULL skb\n");
        return;
    }

    nlh = nlmsg_hdr(skb);
    if (!nlh || !NLMSG_OK(nlh, skb->len)) {
        pr_err("Invalid Netlink message header\n");
        return;
    }

    pid = NETLINK_CB(skb).portid;

    cmd = (char *)nlmsg_data(nlh);
    if (!cmd || !*cmd) {
        netlink_send(pid, "Received empty command data");
        return;
    }

    tmp = kstrdup(cmd, GFP_KERNEL);
    if (!tmp) {
        netlink_send(pid, "Memory allocation failed");
        return;
    }

    token = strsep(&tmp, ";");
    if (!token || !*token) {
        netlink_send(pid, "Empty command type");
        goto cleanup;
    }

    if (strcmp(token, "ur") == 0) {
        is_update = true;
    } else if (strcmp(token, "c") == 0) {
        is_config = true;
    } else if (strcmp(token, "d") == 0) {
        is_delete = true;
    } else if (strcmp(token, "w") == 0) {
        is_whitelist = true;
    } else if (strcmp(token, "r") != 0) {
        netlink_send(pid, "Unknown command type: %s", token);
        goto cleanup;
    }

    if (is_delete) {
        token = strsep(&tmp, ";");
        if (!token || kstrtoint(token, 10, &rule_id)) {
            netlink_send(pid, "Invalid delete rule format");
        } else {
            deleted = delete_rule(rule_id);
            netlink_send(pid, deleted ? "Rule ID %d deleted successfully." 
                                     : "Rule ID %d not found.", rule_id);
        }
        goto cleanup;
    }

    if (is_whitelist) {
        token = strsep(&tmp, ";");
        if (!token) {
            netlink_send(pid, "Missing whitelist operation");
            goto cleanup;
        }

        if (strcmp(token, "a") == 0) {
            // Add to whitelist
            token = strsep(&tmp, ";");
            if (!token) {
                netlink_send(pid, "Missing IP address(es)");
                goto cleanup;
            }

            if (strchr(token, ',')) {
                // Multiple IPs
                process_multi_whitelist_add(pid, token);
            } else {
                // Single IP
                if (!in4_pton(token, -1, (u8 *)&ip, -1, NULL)) {
                    netlink_send(pid, "Invalid IP address: %s", token);
                    goto cleanup;
                }

                if (add_whitelist_ip(ip)) {
                    netlink_send(pid, "IP %pI4 added to whitelist", &ip);
                } else {
                    netlink_send(pid, "Failed to add IP %pI4 (may exist or limit reached)", &ip);
                }
            }
        } else if (strcmp(token, "r") == 0) {
            // Remove from whitelist
            token = strsep(&tmp, ";");
            if (!token || !in4_pton(token, -1, (u8 *)&ip, -1, NULL)) {
                netlink_send(pid, "Invalid IP address for whitelist removal");
                goto cleanup;
            }

            if (remove_whitelist_ip(ip)) {
                netlink_send(pid, "IP %pI4 removed from whitelist", &ip);
            } else {
                netlink_send(pid, "IP %pI4 not found in whitelist", &ip);
            }
        } else {
            netlink_send(pid, "Invalid whitelist operation: %s", token);
        }
        goto cleanup;
    }

    if (is_config) {
        char *mode = NULL;
        int action = -1;
        bool *target_mode = NULL;
        const char *mode_name = NULL;

        mode = strsep(&tmp, ";");
        if (!mode || !*mode) {
            netlink_send(pid, "Missing config mode");
            goto cleanup;
        }

        token = strsep(&tmp, ";");
        if (!token || kstrtoint(token, 10, &action) || (action != 0 && action != 1)) {
            netlink_send(pid, "Config action must be 0 or 1");
            goto cleanup;
        }

        if (strcmp(mode, "s") == 0) {
            target_mode = &stealth_mode;
            mode_name = "stealth";
        } else if (strcmp(mode, "l") == 0) {
            target_mode = &lockdown_mode;
            mode_name = "lockdown";
        } else {
            netlink_send(pid, "Unknown config mode: %s", mode);
            goto cleanup;
        }

        if (target_mode) {
            bool old = *target_mode;
            *target_mode = action;
            netlink_send(pid, "%s mode %s. Previous state: %s",
                        mode_name,
                        action ? "enabled" : "disabled",
                        old ? "enabled" : "disabled");
        }
        flush_arp_cache();
        goto cleanup;
    }

    rule = parse_rule(cmd);
    if (!rule) {
        netlink_send(pid, "Failed to parse rule");
        goto cleanup;
    }

    spin_lock(&rule_lock);
    
    if (is_update) {
        bool found = false;
        for (int i = 0; i < rule_count; i++) {
            if (rules[i].id == rule->id) {
                rules[i] = *rule;
                found = true;
                netlink_send(pid, "Updated rule ID %d", rule->id);
                break;
            }
        }
        if (!found) {
            netlink_send(pid, "Rule ID %d not found", rule->id);
        }
    } else {
        if (rule_count >= MAX_RULES) {
            netlink_send(pid, "Rule limit (%d) reached", MAX_RULES);
        } else if (rule_count > 0 && rule->id != rules[rule_count-1].id + 1) {
            netlink_send(pid, "Expected ID %d, got %d", 
                        rules[rule_count-1].id + 1, rule->id);
        } else {
            rules[rule_count++] = *rule;
            netlink_send(pid, "Added rule ID %d", rule->id);
        }
    }

    spin_unlock(&rule_lock);

cleanup:
    if (rule) kfree(rule);
    if (tmp) kfree(tmp);
}


static int __init firewall_init(void) {
    int ret;

    INIT_LIST_HEAD(&fw_config.whitelist);
    spin_lock_init(&fw_config.whitelist_lock);
    fw_config.whitelist_count = 0;

    struct netlink_kernel_cfg cfg_control = {
        .input = netlink_recv,
    };

    struct netlink_kernel_cfg cfg_log = {
        .input = netlink_log_recv,
        .groups = 1,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg_control);
    if (!nl_sk) {
        pr_err("Failed to create control netlink socket\n");
        return -ENOMEM;
    }

    netlink_log_sock = netlink_kernel_create(&init_net, NETLINK_LOG, &cfg_log);
    if (!netlink_log_sock) {
        pr_err("Failed to create log netlink socket\n");
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
        return -ENOMEM;
    }

    pr_info("Netlink sockets created successfully\n");

    ret = nf_register_net_hooks(&init_net, firewall_ops, ARRAY_SIZE(firewall_ops));
    if (ret < 0) {
        pr_err("Failed to register netfilter hooks\n");
        netlink_kernel_release(nl_sk);
        netlink_kernel_release(netlink_log_sock);
        nl_sk = NULL;
        netlink_log_sock = NULL;
        return ret;
    }

    pr_info("Firewall initialized successfully\n");
    return 0;
}


// Firewall exit modue
static void __exit firewall_exit(void) {
    nf_unregister_net_hooks(&init_net, firewall_ops, ARRAY_SIZE(firewall_ops));

    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        nl_sk = NULL;
    }

    if (netlink_log_sock) {
        netlink_kernel_release(netlink_log_sock);
        netlink_log_sock = NULL;
    }

    pr_info("Firewall disabled\n");
}


// Registering the init and exit handlers.
early_initcall(firewall_init);
module_exit(firewall_exit);
