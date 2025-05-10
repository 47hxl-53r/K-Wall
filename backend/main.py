import socket
import os
import json
import struct
import time
import subprocess
import ctypes
import uvicorn
import ipaddress
import signal
import atexit
import sys
import pytz
import threading
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime
from sqlalchemy.orm import declarative_base
from typing import Optional, List
from pydantic import BaseModel
import pam
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Dict, List
from collections import defaultdict, deque
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

# Update your CORS middleware configuration (replace the existing one)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For development, replace with your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]  # This ensures all headers are exposed to the frontend
)

# Add OPTIONS handler for each endpoint
@app.options("/api")
async def options_root():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "*"
    })

@app.options("/api/auth/login")
async def options_login():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    })

@app.options("/api/rules")
async def options_rules():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/config/{config_type}")
async def options_config():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/whitelist")
async def options_whitelist():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    })

@app.options("/api/delete/{rule_id}")
async def options_delete():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/whitelist/manage")
async def options_whitelist_manage():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    })


@app.options("/api/logs/all")
async def options_logs_all():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })
    
  
@app.options("/api/manage")
async def options_manage():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    })

@app.options("/api/logs/clear")
async def options_logs_clear():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/logs/realtime")
async def options_logs_realtime():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/logs/blocked")
async def options_logs_blocked():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })

@app.options("/api/logs/stats")
async def options_logs_stats():
    return Response(headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization"
    })


pam_auth = pam.pam()

def authenticate_root(credentials: HTTPBasicCredentials):
    # First check if username is root
    if credentials.username != "root":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    # Authenticate with PAM
    if not pam_auth.authenticate(credentials.username, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# Global socket variable
sock = None
NETLINK_USER = 31
DATABASE_URL = 'sqlite:///./.fw.db'
IST = pytz.timezone("Asia/Kolkata")


# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
current_logs = deque(maxlen=1000)  # Using deque for efficient rotation
detailed_blocked_logs = deque(maxlen=500)  # Stores full details of blocked requests
log_stats = defaultdict(int)
log_stats_lock = threading.Lock()
log_thread_running = False



class FirewallLog(Base):
    __tablename__ = "firewall_logs"
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime)
    src_ip = Column(String)
    dst_ip = Column(String)
    src_port = Column(Integer)
    dst_port = Column(Integer)
    protocol = Column(String)
    length = Column(Integer)
    action = Column(String)
    reason = Column(String)
    

class PacketLog(ctypes.Structure):
    _pack_ = 1  # Ensure packed structure to match kernel
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dest_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dest_port", ctypes.c_uint16),
        ("protocol", ctypes.c_int),
        ("packet_len", ctypes.c_uint32),
        ("action", ctypes.c_int),
        ("reason", ctypes.c_char * 32)
    ]

class FirewallRule(Base):
    __tablename__ = "firewall_rules"
    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(Integer, unique=True, index=True)
    action = Column(String)
    direction = Column(String)
    protocol = Column(String)
    port = Column(Integer)
    host = Column(String)
    created_at = Column(DateTime, default=datetime.now(IST))
    updated_at = Column(DateTime, default=datetime.now(IST), onupdate=datetime.now(IST))

class FirewallConfig(Base):
    __tablename__ = "firewall_configs"
    id = Column(Integer, primary_key=True, index=True)
    config_type = Column(String)
    status = Column(String)
    updated_at = Column(DateTime, default=datetime.now(IST), onupdate=datetime.now(IST))

class WhitelistIP(Base):
    __tablename__ = "whitelist_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.now(IST))

Base.metadata.create_all(bind=engine)

# Pydantic models for request/response validation
class RuleModel(BaseModel):
    operation: str
    rule_id: int
    action: str
    direction: str
    protocol: str
    port: int
    host: str

class ConfigModel(BaseModel):
    lockdown: Optional[str] = None
    stealth: Optional[str] = None

class WhitelistModel(BaseModel):
    operation: str  # "add" or "remove"
    ip_address: str

class BlockedLogStats(Base):
    __tablename__ = "blocked_log_stats"
    id = Column(Integer, primary_key=True, index=True)
    reason = Column(String, unique=True, index=True)
    count = Column(Integer, default=0)
    last_updated = Column(DateTime, default=datetime.now(IST), onupdate=datetime.now(IST))


def cleanup():
    global sock
    if sock:
        try:
            sock.close()
        except:
            pass
        sock = None
    print("\nCleanup complete. Resources released.")


def initialize_configs():
    db = SessionLocal()
    try:
        # Initialize lockdown config if not exists
        if not db.query(FirewallConfig).filter(FirewallConfig.config_type == "lockdown").first():
            db.add(FirewallConfig(config_type="lockdown", status="off"))
        
        # Initialize stealth config if not exists
        if not db.query(FirewallConfig).filter(FirewallConfig.config_type == "stealth").first():
            db.add(FirewallConfig(config_type="stealth", status="off"))
        
        db.commit()
    except Exception as e:
        print(f"Error initializing configs: {str(e)}")
        db.rollback()
    finally:
        db.close()

def update_block_stats(log_entry: Dict):
    reason = log_entry['reason']
    with log_stats_lock:
        log_stats[reason] += 1
    
    db = SessionLocal()
    try:
        # Ensure table exists
        Base.metadata.create_all(bind=engine)
        
        db_stat = db.query(BlockedLogStats).filter(BlockedLogStats.reason == reason).first()
        if db_stat:
            db_stat.count += 1
        else:
            db_stat = BlockedLogStats(reason=reason, count=1)
            db.add(db_stat)
        db.commit()
    except Exception as e:
        print(f"Error updating block stats: {str(e)}")
        # Try to create tables if they don't exist
        try:
            Base.metadata.create_all(bind=engine)
        except Exception as e:
            print(f"Failed to create tables: {str(e)}")
    finally:
        db.close()
        

def add_log_to_db(db: Session, log_entry: dict):
    try:
        db_log = FirewallLog(
            timestamp=datetime.fromtimestamp(log_entry['timestamp_ns'] / 1e9),
            src_ip=log_entry['src_ip'],
            dst_ip=log_entry['dst_ip'],
            src_port=log_entry['src_port'],
            dst_port=log_entry['dst_port'],
            protocol=log_entry['protocol'],
            length=log_entry['length'],
            action=log_entry['action'],
            reason=log_entry['reason']
        )
        db.add(db_log)
        db.commit()
        db.refresh(db_log)
        return db_log
    except Exception as e:
        db.rollback()
        print(f"Error saving log to database: {str(e)}")
        return None
        
        
        
def handle_sigterm(signum, frame):
    print(f"\nReceived signal {signum}, shutting down...")
    cleanup()
    sys.exit(0)

def handle_keyboard_interrupt(signum, frame):
    print("\nKeyboard interrupt received, shutting down gracefully...")
    cleanup()
    sys.exit(0)

# Register cleanup handlers
atexit.register(cleanup)
signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_keyboard_interrupt)

def initialize_socket():
    global sock
    if sock is not None:
        return sock
        
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USER)
        s.bind((os.getpid(), 0))
        s.settimeout(5.0)
        sock = s
        return sock
    except Exception as e:
        print(f"Socket initialization failed: {e}")
        raise


def netlink_log_listener():
    global current_logs, log_thread_running
    
    NETLINK_LOG = 30
    NETLINK_GROUP = 1
    
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_LOG)
    s.bind((os.getpid(), NETLINK_GROUP))
    log_thread_running = True
    
    print(f"Started log listener (group {NETLINK_GROUP})...")
    
    # Protocol number to name mapping
    PROTOCOL_MAP = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        4: "OTHER",
        0: "ALL",
    }
    
    try:
        while log_thread_running:
            data = s.recv(4096)
            if not data:
                continue
                
            # Skip 16-byte netlink header
            payload = data[16:]
            
            try:
                log = PacketLog.from_buffer_copy(payload)
                
                # Convert to human-readable format
                timestamp = log.timestamp_ns / 1e9
                src_ip = socket.inet_ntoa(struct.pack("!I", log.src_ip))
                dst_ip = socket.inet_ntoa(struct.pack("!I", log.dest_ip))
                
                # Get protocol name
                protocol_num = log.protocol
                protocol = PROTOCOL_MAP.get(protocol_num, f"UNKNOWN({protocol_num})")
                
                action = "ALLOW" if log.action else "DENY"
                reason = log.reason.decode().strip('\x00')
                
                # Extract original protocol information from reason if this is a rejection
                original_protocol = protocol
                if "Rule denied" in reason:
                    if "TCP" in reason:
                        original_protocol = "TCP"
                    elif "UDP" in reason:
                        original_protocol = "UDP"
                    elif "ICMP" in reason:
                        original_protocol = "ICMP"
                
                # For blocked packets, we want to log the original protocol, not the ICMP response
                if action == "DENY" and protocol in ["ICMP", "ICMPv6"]:
                    protocol = original_protocol
                
                log_entry = {
                    "timestamp": time.ctime(timestamp),
                    "timestamp_ns": log.timestamp_ns,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": log.src_port,
                    "dst_port": log.dest_port,
                    "protocol": protocol,
                    "length": log.packet_len,
                    "action": action,
                    "reason": reason
                }
                
                # Store in memory
                current_logs.append(log_entry)
                
                # Store in database
                db = SessionLocal()
                try:
                    add_log_to_db(db, log_entry)
                except Exception as e:
                    print(f"Error saving log to database: {str(e)}")
                finally:
                    db.close()
                
                # Store detailed blocked logs if action is DENY
                if action == "DENY":
                    detailed_blocked_logs.append(log_entry)
                    update_block_stats(log_entry)
                    
            except Exception as e:
                print(f"Error parsing log entry: {str(e)}")
                continue
                
    except Exception as e:
        print(f"Log listener error: {str(e)}")
    finally:
        s.close()
        log_thread_running = False
        
        
def start_log_listener():
    if not log_thread_running:
        log_thread = threading.Thread(target=netlink_log_listener, daemon=True)
        log_thread.start()
        return True
    return False



def clear_logs():
    global current_logs, detailed_blocked_logs, log_stats
    with log_stats_lock:
        current_logs.clear()
        detailed_blocked_logs.clear()
        log_stats.clear()
    return True


def parse_config(config: dict) -> str:
    if not isinstance(config, dict):
        return "Invalid config format"
    
    if 'lockdown' in config and config['lockdown'] in ["on", "off"]:
        return f"c;l;{1 if config['lockdown'] == 'on' else 0}"
    elif 'stealth' in config and config['stealth'] in ["on", "off"]:
        return f"c;s;{1 if config['stealth'] == 'on' else 0}"
    return "No valid config option provided"

def parse_rule(rule: dict) -> str:
    if len(rule) != 7:
        return "Parsing failed: Invalid rule structure"

    try:
        # Validate operation
        operation = rule.get('operation')
        if operation not in ["add", "update"]:
            return "Invalid operation"
        
        # Validate rule_id
        rule_id = rule.get('rule_id')
        if not isinstance(rule_id, int) or rule_id <= 0:
            return "Invalid rule ID"
        
        # Validate action
        action = rule.get('action')
        if action not in ["allow", "deny"]:
            return "Invalid action"
        
        # Validate direction
        direction = rule.get('direction')
        if direction not in ["in", "out"]:
            return "Invalid direction"
        
        # Validate protocol
        protocol = rule.get('protocol', '').lower()
        if protocol not in ["tcp", "udp", "all"]:
            return "Invalid protocol"
        
        # Validate port
        port = rule.get('port')
        if not isinstance(port, int) or not (0 <= port <= 65535):
            return "Invalid port"
        
        # Validate host
        host = rule.get('host')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return "Invalid host IP"

        # Build the command string
        cmd = "ur;" if operation == "update" else "r;"
        cmd += f"{rule_id};"
        cmd += "1;" if action == "allow" else "0;"
        cmd += "1;" if direction == "in" else "0;"
        cmd += f"{protocol};{port};{host};"
        
        return cmd
    except Exception as e:
        return f"Parsing error: {str(e)}"

def parse_whitelist(whitelist: dict) -> str:
    if not isinstance(whitelist, dict):
        return "Invalid whitelist format"
    
    operation = whitelist.get('operation')
    ip_address = whitelist.get('ip_address')
    
    if operation not in ["add", "remove"]:
        return "Invalid whitelist operation"
    
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return "Invalid IP address"
    
    return f"w;{'a' if operation == 'add' else 'r'};{ip_address}"

def send_kernel(msg: str) -> str:
    global sock
    try:
        if sock is None:
            sock = initialize_socket()
            if sock is None:
                return "Failed to initialize socket"
                
        msg = msg.encode()
        nlh = struct.pack("IHHII", len(msg) + 16, 0, 0, os.getpid(), 0)
        sock.sendall(nlh + msg)
        
        response = sock.recv(4096)
        if not response:
            return "Empty response from kernel"
            
        nl_len = struct.unpack("I", response[:4])[0]
        return response[16:nl_len].decode().rstrip('\x00')
        
    except socket.timeout:
        return "Timeout waiting for response"
    except Exception as e:
        return f"Communication error: {str(e)}"

def load_kernel_module() -> bool:
    try:
        if not is_already_loaded():
            print("Loading kernel module...")
            result = subprocess.run(["sudo", "modprobe", "kwall"], check=True, capture_output=True)
            if result.returncode != 0:
                print(f"Failed to load module: {result.stderr.decode()}")
                return False
            time.sleep(2)  # Allow module to initialize
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error loading module: {e.stderr.decode()}")
        return False
    except Exception as e:
        print(f"Unexpected error loading module: {str(e)}")
        return False

def is_already_loaded() -> bool:
    try:
        output = subprocess.check_output(['lsmod']).decode()
        return "kwall" in output
    except Exception:
        return False

# Database operations
def add_rule_to_db(db: Session, rule: dict) -> FirewallRule:
    db_rule = FirewallRule(
        rule_id=rule['rule_id'],
        action=rule['action'],
        direction=rule['direction'],
        protocol=rule['protocol'],
        port=rule['port'],
        host=rule['host']
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)
    return db_rule

def update_rule_in_db(db: Session, rule: dict) -> FirewallRule:
    db_rule = db.query(FirewallRule).filter(FirewallRule.rule_id == rule['rule_id']).first()
    if db_rule:
        db_rule.action = rule['action']
        db_rule.direction = rule['direction']
        db_rule.protocol = rule['protocol']
        db_rule.port = rule['port']
        db_rule.host = rule['host']
        db.commit()
        db.refresh(db_rule)
    return db_rule

def rule_exists(db: Session, rule_id: int) -> bool:
    return db.query(FirewallRule).filter(FirewallRule.rule_id == rule_id).first() is not None

def delete_rule_from_db(db: Session, rule_id: int) -> bool:
    db_rule = db.query(FirewallRule).filter(FirewallRule.rule_id == rule_id).first()
    if db_rule:
        db.delete(db_rule)
        db.commit()
        return True
    return False

def update_config_in_db(db: Session, config_type: str, status: str) -> FirewallConfig:
    db_config = db.query(FirewallConfig).filter(FirewallConfig.config_type == config_type).first()
    if db_config:
        db_config.status = status
    else:
        db_config = FirewallConfig(config_type=config_type, status=status)
        db.add(db_config)
    db.commit()
    db.refresh(db_config)
    return db_config

def get_config(db: Session, config_type: str) -> Optional[FirewallConfig]:
    return db.query(FirewallConfig).filter(FirewallConfig.config_type == config_type).first()

def get_all_rules(db: Session) -> List[FirewallRule]:
    return db.query(FirewallRule).order_by(FirewallRule.rule_id).all()

def add_whitelist_ip(db: Session, ip_address: str) -> WhitelistIP:
    # Check if IP already exists
    if db.query(WhitelistIP).filter(WhitelistIP.ip_address == ip_address).first():
        raise ValueError("IP already exists in whitelist")
    
    db_ip = WhitelistIP(ip_address=ip_address)
    db.add(db_ip)
    db.commit()
    db.refresh(db_ip)
    return db_ip

def remove_whitelist_ip(db: Session, ip_address: str) -> bool:
    db_ip = db.query(WhitelistIP).filter(WhitelistIP.ip_address == ip_address).first()
    if db_ip:
        db.delete(db_ip)
        db.commit()
        return True
    return False

def get_all_whitelist_ips(db: Session) -> List[WhitelistIP]:
    return db.query(WhitelistIP).order_by(WhitelistIP.ip_address).all()

def whitelist_ip_exists(db: Session, ip_address: str) -> bool:
    return db.query(WhitelistIP).filter(WhitelistIP.ip_address == ip_address).first() is not None

# Loading functions
def load_configs():
    db = SessionLocal()
    try:
        configs = db.query(FirewallConfig).all()
        for config in configs:
            config_dict = {config.config_type: config.status}
            parsed_config = parse_config(config_dict)
            if not parsed_config.startswith(("Error", "Invalid")):
                response = send_kernel(parsed_config)
                if response.startswith(("Error", "Invalid")):
                    print(f"Failed to load config {config.config_type}: {response}")
    except Exception as e:
        print(f"Error loading configs: {str(e)}")
    finally:
        db.close()

def load_rules():
    db = SessionLocal()
    try:
        rules = get_all_rules(db)
        if rules:
            for rule in rules:
                rule_dict = {
                    "operation": "add",
                    "rule_id": rule.rule_id,
                    "action": rule.action,
                    "direction": rule.direction,
                    "protocol": rule.protocol,
                    "port": rule.port,
                    "host": rule.host
                }
                parsed_rule = parse_rule(rule_dict)
                if not parsed_rule.startswith(("Error", "Invalid")):
                    response = send_kernel(parsed_rule)
                    if response.startswith(("Error", "Invalid")):
                        print(f"Failed to load rule {rule.rule_id}: {response}")
            print(f"Loaded {len(rules)} rules into kernel.")
        else:
            print("No rules in database to load")
    except Exception as e:
        print(f"Error loading rules: {str(e)}")
    finally:
        db.close()

def load_whitelist():
    db = SessionLocal()
    try:
        whitelist_ips = get_all_whitelist_ips(db)
        if whitelist_ips:
            for ip in whitelist_ips:
                whitelist_cmd = parse_whitelist({"operation": "add", "ip_address": ip.ip_address})
                if not whitelist_cmd.startswith(("Error", "Invalid")):
                    response = send_kernel(whitelist_cmd)
                    if response.startswith(("Error", "Invalid")):
                        print(f"Failed to load whitelist IP {ip.ip_address}: {response}")
            print(f"Loaded {len(whitelist_ips)} whitelist IPs into kernel.")
        else:
            print("No whitelist IPs in database to load")
    except Exception as e:
        print(f"Error loading whitelist: {str(e)}")
    finally:
        db.close()

# API Endpoints
@app.get("/api")
def root():
    return {"message": "K-Wall is running"}


@app.post("/api/auth/login")
def login(username: str = Depends(authenticate_root)):
    return {
        "status": "success",
        "message": "Authentication successful",
        "user": username
    }
    
  
    
@app.get("/api/rules")
def get_rules_handler():
    db = SessionLocal()
    try:
        rules = get_all_rules(db)
        return {
            "rules": [{
                "rule_id": rule.rule_id,
                "action": rule.action,
                "direction": rule.direction,
                "protocol": rule.protocol,
                "port": rule.port,
                "host": rule.host,
                "created_at": rule.created_at.astimezone(IST).isoformat(),
                "updated_at": rule.updated_at.astimezone(IST).isoformat() if rule.updated_at else None
            } for rule in rules]
        }
    finally:
        db.close()

@app.get("/api/rules/next_rule_id")
def get_next_rule_id():
    db = SessionLocal()
    try:
        # Get the highest rule_id currently in the database
        max_id = db.query(func.max(FirewallRule.rule_id)).scalar()
        
        # If no rules exist yet, start with 1
        next_id = 1 if max_id is None else max_id + 1
        
        return {
            "rule_id": next_id
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        db.close()
        
        

@app.get("/api/config/{config_type}")
def get_config_handler(config_type: str):
    db = SessionLocal()
    try:
        if config_type not in ['lockdown', 'stealth']:
            return {"status": "error", "message": f"Config '{config_type}' not found"}

        config = db.query(FirewallConfig).filter(FirewallConfig.config_type == config_type).first()
        
        if not config:
            config = FirewallConfig(config_type=config_type, status="off")
            db.add(config)
            db.commit()
            db.refresh(config)
                        
        return {
            "config_type": config_type,
            "status": config.status,
            "updated_at": config.updated_at.astimezone(IST).isoformat()
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

@app.get("/api/whitelist")
def get_whitelist_handler():
    db = SessionLocal()
    try:
        whitelist_ips = get_all_whitelist_ips(db)
        return {
            "whitelist": [{
                "ip_address": ip.ip_address,
                "created_at": ip.created_at.astimezone(IST).isoformat()
            } for ip in whitelist_ips]
        }
    finally:
        db.close()

@app.delete("/api/delete/{rule_id}")
async def delete_handler(rule_id: int):
    db = SessionLocal()
    try:
        if not rule_exists(db, rule_id):
            return {"status": "failed", "message": f"Rule ID {rule_id} not found"}
        
        response = send_kernel(f"d;{rule_id}")
        if response and not response.startswith(("Error", "Timeout", "Failed")):
            if delete_rule_from_db(db, rule_id):
                return {"status": "success", "message": f"Rule ID {rule_id} deleted"}
            return {"status": "success", "message": f"Rule deleted from kernel but not found in database"}
        return {"status": "failed", "message": response}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

@app.post("/api/whitelist/manage")
async def whitelist_handler(request: Request):
    db = SessionLocal()
    try:
        body = await request.json()
        whitelist_model = WhitelistModel(**body)
        
        parsed_cmd = parse_whitelist(body)
        if parsed_cmd.startswith(("Error", "Invalid")):
            return {"status": "failed", "message": parsed_cmd}
            
        response = send_kernel(parsed_cmd)
        if response and not response.startswith(("Error", "Timeout", "Failed")):
            if body['operation'] == "add":
                try:
                    add_whitelist_ip(db, body['ip_address'])
                except ValueError as e:
                    return {"status": "failed", "message": str(e)}
            elif body['operation'] == "remove":
                if not remove_whitelist_ip(db, body['ip_address']):
                    return {"status": "failed", "message": f"IP {body['ip_address']} not found in whitelist"}
            
            return {"status": "success", "message": response}
        return {"status": "failed", "message": response}
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        db.close()

@app.post("/api/manage")
async def manage_handler(request: Request):
    db = SessionLocal()
    try:
        body = await request.json()
        
        if "rule" in body:
            rule_model = RuleModel(**body['rule'])
            parsed_rule = parse_rule(body['rule'])
            if parsed_rule.startswith(("Error", "Invalid")):
                return {"status": "failed", "message": parsed_rule}
                
            response = send_kernel(parsed_rule)
            if response and not response.startswith(("Error", "Timeout", "Failed")):
                if body['rule']['operation'] == "add":
                    if rule_exists(db, body['rule']['rule_id']):
                        return {"status": "failed", "message": f"Rule ID {body['rule']['rule_id']} exists"}
                    add_rule_to_db(db, body['rule'])
                elif body['rule']['operation'] == "update":
                    if not rule_exists(db, body['rule']['rule_id']):
                        return {"status": "failed", "message": f"Rule ID {body['rule']['rule_id']} doesn't exist"}
                    update_rule_in_db(db, body['rule'])
                return {"status": "success", "message": response}
            return {"status": "failed", "message": response}

        if "config" in body:
            config_model = ConfigModel(**body['config'])
            parsed_config = parse_config(body['config'])
            if parsed_config.startswith(("Error", "Invalid")):
                return {"status": "failed", "message": parsed_config}
                
            response = send_kernel(parsed_config)
            if response and not response.startswith(("Error", "Timeout", "Failed")):
                if 'lockdown' in body['config']:
                    update_config_in_db(db, "lockdown", body['config']['lockdown'])
                elif 'stealth' in body['config']:
                    update_config_in_db(db, "stealth", body['config']['stealth'])
                return {"status": "success", "message": response}
            return {"status": "failed", "message": response}
            
        return {"status": "error", "message": "Invalid request"}
    except json.JSONDecodeError:
        return {"status": "error", "message": "Invalid JSON"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        db.close()


@app.get("/api/logs/all")
def get_all_logs(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    action: Optional[str] = None,
    protocol: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    min_port: Optional[int] = None,
    max_port: Optional[int] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    srv: bool = False
):
    """
    Get all logs from database with filtering options
    Parameters:
    - limit: Number of logs to return (default: 100)
    - offset: Pagination offset (default: 0)
    - action: Filter by action (ALLOW/DENY)
    - protocol: Filter by protocol (TCP/UDP/ICMP)
    - src_ip: Filter by source IP
    - dst_ip: Filter by destination IP
    - min_port: Minimum port number
    - max_port: Maximum port number
    - date_from: Start date (YYYY-MM-DD)
    - date_to: End date (YYYY-MM-DD)
    - srv: Include server (port 9876) logs (default: False)
    """
    db = SessionLocal()
    try:
        query = db.query(FirewallLog)
        
        # Apply filters
        if action:
            query = query.filter(FirewallLog.action == action.upper())
        if protocol:
            query = query.filter(FirewallLog.protocol == protocol.upper())
        if src_ip:
            query = query.filter(FirewallLog.src_ip == src_ip)
        if dst_ip:
            query = query.filter(FirewallLog.dst_ip == dst_ip)
        if min_port is not None:
            query = query.filter(
                (FirewallLog.src_port >= min_port) | 
                (FirewallLog.dst_port >= min_port)
            )
        if max_port is not None:
            query = query.filter(
                (FirewallLog.src_port <= max_port) | 
                (FirewallLog.dst_port <= max_port)
            )
        if date_from:
            try:
                date_from_dt = datetime.strptime(date_from, "%Y-%m-%d")
                query = query.filter(FirewallLog.timestamp >= date_from_dt)
            except ValueError:
                pass
        if date_to:
            try:
                date_to_dt = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)
                query = query.filter(FirewallLog.timestamp < date_to_dt)
            except ValueError:
                pass
        
        # Filter out server logs if srv is False
        if not srv:
            query = query.filter(
                (FirewallLog.src_port != 9876) & 
                (FirewallLog.dst_port != 9876)
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        logs = query.order_by(FirewallLog.timestamp.desc()).offset(offset).limit(limit).all()
        
        # Build response
        response = {
            "logs": [{
                "id": log.id,
                "timestamp": log.timestamp.astimezone(IST).isoformat(),
                "src_ip": log.src_ip,
                "dst_ip": log.dst_ip,
                "src_port": log.src_port,
                "dst_port": log.dst_port,
                "protocol": log.protocol,
                "length": log.length,
                "action": log.action,
                "reason": log.reason
            } for log in logs],
            "total": total,
            "limit": limit,
            "offset": offset,
            "server_logs_included": srv,
            "filters": {
                "action": action,
                "protocol": protocol,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "min_port": min_port,
                "max_port": max_port,
                "date_from": date_from,
                "date_to": date_to
            }
        }
        print(response)
        return response
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )
    finally:
        db.close()



@app.delete("/api/logs/clear")
def clear_logs():
    """Clear ALL logs (realtime, blocked, stats, and database logs)"""
    global current_logs, detailed_blocked_logs, log_stats
    
    try:
        # Clear all in-memory logs
        current_logs.clear()
        detailed_blocked_logs.clear()
        
        # Clear statistics
        with log_stats_lock:
            log_stats.clear()
        
        # Clear all database logs
        db = SessionLocal()
        try:
            # Clear all log-related tables
            db.query(BlockedLogStats).delete()
            
            # If you have a FirewallLog table (from previous implementation)
            if 'firewall_logs' in Base.metadata.tables:
                db.query(FirewallLog).delete()
            
            db.commit()
        except Exception as e:
            db.rollback()
            return {
                "status": "error",
                "message": f"Database clearing failed: {str(e)}"
            }
        finally:
            db.close()
        
        return {
            "status": "success",
            "message": "All logs cleared successfully"
        }
            
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


@app.get("/api/logs/realtime")
def get_realtime_logs(limit: int = 100, srv: bool = False):
    """Get recent in-memory logs
    Parameters:
    - limit: number of logs to return (default: 100)
    - srv: include server (port 9876) logs (default: False)
    """
    # Get all logs if limit is 0 or negative, otherwise get the most recent [limit] logs
    all_logs = list(current_logs)
    logs = all_logs[-limit:] if limit > 0 else all_logs
    
    if not srv:
        # Filter out logs where either source OR destination port is 9876
        logs = [
            log for log in logs 
            if log.get('src_port') != 9876 and log.get('dst_port') != 9876
        ]
    
    return {
        "logs": logs,
        "count": len(logs),
        "server_logs_included": srv,
        "total_logs_available": len(all_logs)
    }
  
    
@app.get("/api/logs/blocked")
def get_blocked_logs(limit: int = 100):
    """Get detailed information about blocked requests"""
    return {
        "blocked_requests": list(detailed_blocked_logs)[-limit:],
        "total_blocked": len(detailed_blocked_logs)
    }


@app.get("/api/logs/stats")
def get_complete_stats():
    """Get comprehensive statistics including allowed and blocked requests (excluding server traffic)"""
    db = SessionLocal()
    try:
        # Calculate allowed requests (excluding server traffic)
        allowed_count = sum(
            1 for log in current_logs 
            if log['action'] == 'ALLOW' 
            and log.get('dst_port') != 9876 
            and log.get('src_port') != 9876
        )
        
        # Get blocked stats from database and current session
        blocked_stats = defaultdict(int)
        
        # Add database stats
        db_stats = db.query(BlockedLogStats).all()
        for stat in db_stats:
            blocked_stats[stat.reason] += stat.count
        
        # Add current session stats
        with log_stats_lock:
            for reason, count in log_stats.items():
                blocked_stats[reason] += count
        
        # Convert to sorted list
        sorted_blocked = sorted(
            [{"reason": k, "count": v} for k, v in blocked_stats.items()],
            key=lambda x: x['count'],
            reverse=True
        )
        
        # Prepare chart data
        reasons = [stat['reason'] for stat in sorted_blocked]
        counts = [stat['count'] for stat in sorted_blocked]
        
        return {
            "stats": {
                "allowed": allowed_count,
                "blocked": sum(counts),
                "blocked_details": sorted_blocked
            },
            "chart_data": {
                "labels": ["Allowed", "Blocked"] + reasons,
                "datasets": [
                    {
                        "label": "Request Types",
                        "data": [allowed_count, sum(counts)] + [0] * len(reasons),
                        "backgroundColor": ["#36a2eb", "#ff6384"] + ["#ff9f40"] * len(reasons)
                    },
                    {
                        "label": "Blocked Reasons",
                        "data": [0, 0] + counts,
                        "backgroundColor": ["#36a2eb", "#ff6384"] + ["#ffcd56"] * len(reasons)
                    }
                ]
            }
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        db.close()
 
 

if __name__ == '__main__':
    print("Starting K-Wall firewall service...")
    
    # Initialize database tables and default configs
    Base.metadata.create_all(bind=engine)
    initialize_configs()
    
    if not load_kernel_module():
        print("Failed to load kernel module. Exiting.")
        sys.exit(1)
        
    try:
        initialize_socket()
        load_rules()
        load_configs()
        load_whitelist()
        
        if not start_log_listener():
            print("Failed to start log listener")
        
        print("Starting API server on port 9876")
        print("Press Ctrl+C to stop the server")
        uvicorn.run(app, host='0.0.0.0', port=9876)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Failed to start service: {str(e)}")
    finally:
        cleanup()
        sys.exit(0)
