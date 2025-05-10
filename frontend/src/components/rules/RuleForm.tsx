
import * as z from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Info } from "lucide-react";

interface RuleFormData {
  rule_id?: number;
  action: "allow" | "deny";
  direction: "in" | "out";
  protocol: "tcp" | "udp" | "all";
  port: number;
  host: string;
}

interface RuleFormProps {
  initialData?: RuleFormData;
  onSubmit: (data: RuleFormData) => void;
  onCancel: () => void;
}

// Define validation schema
const ruleFormSchema = z.object({
  rule_id: z.number().optional(),
  action: z.enum(["allow", "deny"]),
  direction: z.enum(["in", "out"]),
  protocol: z.enum(["tcp", "udp", "all"]),
  port: z.number().min(0).max(65535),
  host: z.string().min(1, "Host is required"),
});

export function RuleForm({ initialData, onSubmit, onCancel }: RuleFormProps) {
  const form = useForm<z.infer<typeof ruleFormSchema>>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: initialData || {
      action: "allow",
      direction: "in",
      protocol: "tcp",
      port: 80,
      host: "",
    },
  });

  const isSubmitSuccessful = form.formState.isSubmitSuccessful;
  const errors = form.formState.errors;
  const hasErrors = Object.keys(errors).length > 0;

  const handleFormSubmit = (data: z.infer<typeof ruleFormSchema>) => {
    onSubmit(data as RuleFormData);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleFormSubmit)} className="space-y-4">
        {hasErrors && !isSubmitSuccessful && (
          <Alert variant="destructive" className="mb-4">
            <Info className="h-4 w-4 mr-2" />
            <AlertDescription>
              Please fill out all required fields correctly before submitting.
            </AlertDescription>
          </Alert>
        )}

        <FormField
          control={form.control}
          name="action"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Action</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select action" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="allow">Allow</SelectItem>
                  <SelectItem value="deny">Deny</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="direction"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Direction</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select direction" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="in">Inbound</SelectItem>
                  <SelectItem value="out">Outbound</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="protocol"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Protocol</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger>
                    <SelectValue placeholder="Select protocol" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                  <SelectItem value="all">All</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="port"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Port</FormLabel>
              <FormControl>
                <Input
                  type="number"
                  min={0}
                  max={65535}
                  {...field}
                  onChange={(e) => field.onChange(parseInt(e.target.value, 10) || 0)}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="host"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Host</FormLabel>
              <FormControl>
                <Input {...field} placeholder="Enter IP address" />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end space-x-2">
          <Button type="button" variant="outline" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit">
            {initialData ? "Update Rule" : "Add Rule"}
          </Button>
        </div>
      </form>
    </Form>
  );
}

