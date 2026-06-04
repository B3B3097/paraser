import { useState } from "react";
import { useListConfigs, getListConfigsQueryKey, useClearConfigs, ListConfigsStatus, ListConfigsCheckLevel } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Trash2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Configs() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  
  const [status, setStatus] = useState<ListConfigsStatus | "">("");
  const [checkLevel, setCheckLevel] = useState<ListConfigsCheckLevel | "">("");

  const queryParams = {
    ...(status ? { status } : {}),
    ...(checkLevel ? { checkLevel } : {})
  };

  const { data: configs, isLoading } = useListConfigs(queryParams, {
    query: {
      enabled: true,
      queryKey: getListConfigsQueryKey(queryParams),
    }
  });

  const clearConfigs = useClearConfigs();

  const handleClear = () => {
    if (!window.confirm("Are you sure you want to delete ALL configs?")) return;
    clearConfigs.mutate(undefined, {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListConfigsQueryKey() });
        toast({ title: "Configs cleared" });
      }
    });
  };

  const truncateUuid = (uuid: string) => {
    return uuid.substring(0, 8) + "...";
  };

  const StatusBadge = ({ status, type }: { status?: string | null, type: string }) => {
    if (!status) return <Badge variant="outline" className="font-mono text-[10px] bg-background text-muted-foreground border-muted-foreground/30">{type}:--</Badge>;
    if (status === "ok") return <Badge variant="outline" className="font-mono text-[10px] bg-green-500/10 text-green-400 border-green-500/30">{type}:OK</Badge>;
    return <Badge variant="outline" className="font-mono text-[10px] bg-destructive/10 text-destructive border-destructive/30">{type}:FAIL</Badge>;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/configs</h1>
          <p className="text-muted-foreground mt-2 font-mono text-sm">Parsed VLESS configurations database.</p>
        </div>
        <Button variant="destructive" onClick={handleClear} disabled={clearConfigs.isPending} className="font-mono">
          <Trash2 className="mr-2 h-4 w-4" />
          CLEAR_DB
        </Button>
      </div>

      <Card className="bg-card border-border">
        <CardHeader className="pb-4">
          <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
            <div>
              <CardTitle className="text-lg font-mono">Proxy_Nodes</CardTitle>
              <CardDescription className="font-mono">Showing {configs?.length ?? 0} configs</CardDescription>
            </div>
            <div className="flex gap-2">
              <Select value={status} onValueChange={(val: any) => setStatus(val === "all" ? "" : val)}>
                <SelectTrigger className="w-[140px] font-mono bg-background">
                  <SelectValue placeholder="Status: All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="unchecked">Unchecked</SelectItem>
                  <SelectItem value="working">Working</SelectItem>
                  <SelectItem value="failed">Failed</SelectItem>
                </SelectContent>
              </Select>
              <Select value={checkLevel} onValueChange={(val: any) => setCheckLevel(val === "all" ? "" : val)}>
                <SelectTrigger className="w-[140px] font-mono bg-background">
                  <SelectValue placeholder="Level: All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Levels</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="tls">TLS</SelectItem>
                  <SelectItem value="http">HTTP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border border-border bg-background/50">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="font-mono w-[80px]">UUID</TableHead>
                  <TableHead className="font-mono">HOST:PORT</TableHead>
                  <TableHead className="font-mono">NAME</TableHead>
                  <TableHead className="font-mono">STATUS</TableHead>
                  <TableHead className="font-mono text-right">LATENCY</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground font-mono">
                      Loading configs...
                    </TableCell>
                  </TableRow>
                ) : configs?.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8 text-muted-foreground font-mono">
                      No configs found matching criteria.
                    </TableCell>
                  </TableRow>
                ) : (
                  configs?.map((config) => (
                    <TableRow key={config.id} className="border-border hover:bg-accent/50 group">
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {truncateUuid(config.uuid)}
                      </TableCell>
                      <TableCell className="font-mono text-sm font-medium">
                        {config.host}:{config.port}
                      </TableCell>
                      <TableCell className="font-mono text-sm max-w-[200px] truncate text-muted-foreground">
                        {config.name}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          <StatusBadge status={config.tcpStatus} type="TCP" />
                          <StatusBadge status={config.tlsStatus} type="TLS" />
                          <StatusBadge status={config.httpStatus} type="HTTP" />
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm text-right">
                        {config.latencyMs ? (
                          <span className={config.latencyMs < 500 ? "text-green-400" : config.latencyMs < 1000 ? "text-yellow-400" : "text-destructive"}>
                            {config.latencyMs}ms
                          </span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}