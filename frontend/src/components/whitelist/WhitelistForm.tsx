
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Plus } from "lucide-react";

// IP validation schema
const ipSchema = z.object({
  ip: z.string().refine(
    (val) => {
      // Basic IP validation using regex pattern
      return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(val);
    },
    {
      message: "Please enter a valid IPv4 address (e.g., 192.168.1.1)",
    }
  ),
});

interface WhitelistFormProps {
  onAddIp: (ip: string) => void;
  isLoading: boolean;
}

export function WhitelistForm({ onAddIp, isLoading }: WhitelistFormProps) {
  const form = useForm<z.infer<typeof ipSchema>>({
    resolver: zodResolver(ipSchema),
    defaultValues: {
      ip: "",
    },
  });

  const onSubmit = (data: z.infer<typeof ipSchema>) => {
    onAddIp(data.ip);
    form.reset();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add IP to Whitelist</CardTitle>
        <CardDescription>
          Whitelisted IP addresses will bypass all firewall rules
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="flex space-x-2">
            <FormField
              control={form.control}
              name="ip"
              render={({ field }) => (
                <FormItem className="flex-1">
                  <FormControl>
                    <Input
                      placeholder="Enter IP address (e.g., 192.168.1.1)"
                      {...field}
                      autoComplete="off"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" disabled={isLoading}>
              <Plus className="mr-1 h-4 w-4" /> Add IP
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}
