import { useState } from "react";
import { useCheckConfigs, useGetCheckerStatus, getGetCheckerStatusQueryKey, getGetConfigStatsQueryKey, getListConfigsQueryKey } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Play, Activity, CheckCircle, XCircle, Clock } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Checker() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [level, setLevel] = useState<"tcp" | "tls" | "http">("tcp");
  const [concurrency, setConcurrency] = useState("10");
  const [timeoutMs, setTimeoutMs] = useState("5000");

  const { data: status, isLoading } = useGetCheckerStatus({
    query: {
      queryKey: getGetCheckerStatusQueryKey(),
      refetchInterval: (query) => (query.state.data?.running ? 1500 : false),
    },
  });

  const checkMutation = useCheckConfigs({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getGetCheckerStatusQueryKey() });
        toast({ title: "Check started", description: `Running ${level.toUpperCase()} checks...` });
      },
      onError: () => {
        toast({ title: "Error", description: "Failed to start check job", variant: "destructive" });
      },
    },
  });

  const handleStart = () => {
    checkMutation.mutate({
      data: {
        level,
        concurrency: parseInt(concurrency, 10),
        timeoutMs: parseInt(timeoutMs, 10),
      },
    });
  };

  const progress = status && status.total > 0 ? Math.round((status.checked / status.total) * 100) : 0;

  const levelColors: Record<string, string> = {
    tcp: "text-cyan-400",
    tls: "text-yellow-400",
    http: "text-green-400",
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/checker</h1>
        <p className="text-muted-foreground mt-2 font-mono text-sm">Run connectivity checks against VLESS endpoints.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">Check Configuration</CardTitle>
            <CardDescription className="font-mono text-xs">Select parameters and start the check job</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Check Level</label>
              <Select value={level} onValueChange={(v) => setLevel(v as "tcp" | "tls" | "http")}>
                <SelectTrigger data-testid="select-level" className="font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP — Basic socket connection</SelectItem>
                  <SelectItem value="tls">TLS — TCP + TLS handshake</SelectItem>
                  <SelectItem value="http">HTTP — TLS + HTTP response</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Concurrency</label>
                <Select value={concurrency} onValueChange={setConcurrency}>
                  <SelectTrigger data-testid="select-concurrency" className="font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {[5, 10, 20, 30, 50].map((n) => (
                      <SelectItem key={n} value={String(n)}>{n} threads</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Timeout</label>
                <Select value={timeoutMs} onValueChange={setTimeoutMs}>
                  <SelectTrigger data-testid="select-timeout" className="font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="3000">3s</SelectItem>
                    <SelectItem value="5000">5s</SelectItem>
                    <SelectItem value="10000">10s</SelectItem>
                    <SelectItem value="15000">15s</SelectItem>
                    <SelectItem value="30000">30s</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <Button
              data-testid="button-start-check"
              className="w-full font-mono"
              onClick={handleStart}
              disabled={status?.running || checkMutation.isPending}
            >
              <Play className="w-4 h-4 mr-2" />
              {status?.running ? "Check Running..." : `Start ${level.toUpperCase()} Check`}
            </Button>
          </CardContent>
        </Card>

        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">Job Status</CardTitle>
            <CardDescription className="font-mono text-xs">
              {status?.running ? (
                <span className="flex items-center gap-2">
                  <Activity className="w-3 h-3 animate-pulse text-green-400" />
                  <span className="text-green-400">Running</span>
                  {status.level && <span className={`${levelColors[status.level]} uppercase`}>— {status.level}</span>}
                </span>
              ) : "Idle"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {status && status.total > 0 && (
              <>
                <div className="space-y-2">
                  <div className="flex justify-between font-mono text-xs text-muted-foreground">
                    <span>Progress</span>
                    <span data-testid="text-progress">{status.checked} / {status.total} ({progress}%)</span>
                  </div>
                  <Progress value={progress} className="h-2" />
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-green-950/30 border border-green-900/40 rounded-lg p-3 text-center">
                    <div className="flex items-center justify-center gap-1 mb-1">
                      <CheckCircle className="w-3 h-3 text-green-400" />
                      <span className="font-mono text-xs text-green-400 uppercase">Working</span>
                    </div>
                    <span data-testid="text-working" className="font-mono text-2xl font-bold text-green-400">{status.working}</span>
                  </div>
                  <div className="bg-red-950/30 border border-red-900/40 rounded-lg p-3 text-center">
                    <div className="flex items-center justify-center gap-1 mb-1">
                      <XCircle className="w-3 h-3 text-red-400" />
                      <span className="font-mono text-xs text-red-400 uppercase">Failed</span>
                    </div>
                    <span data-testid="text-failed" className="font-mono text-2xl font-bold text-red-400">{status.failed}</span>
                  </div>
                </div>

                {status.startedAt && (
                  <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    <span>Started: {new Date(status.startedAt).toLocaleTimeString()}</span>
                  </div>
                )}
              </>
            )}

            {(!status || status.total === 0) && !status?.running && (
              <div className="text-center py-8 font-mono text-sm text-muted-foreground">
                No check job run yet. Configure and start a check above.
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">Check Levels Explained</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { level: "TCP", color: "cyan", desc: "Opens a raw TCP socket to host:port. Fastest check — verifies the endpoint is reachable at the network level." },
              { level: "TLS", color: "yellow", desc: "TCP + performs a TLS handshake. Verifies the server accepts encrypted connections (required for most VLESS configs)." },
              { level: "HTTP", color: "green", desc: "TLS + sends an HTTP GET request. Most thorough — verifies the endpoint responds to actual traffic." },
            ].map(({ level: l, color, desc }) => (
              <div key={l} className={`border border-${color}-900/40 bg-${color}-950/20 rounded-lg p-4`}>
                <Badge variant="outline" className={`font-mono text-${color}-400 border-${color}-700 mb-2`}>{l}</Badge>
                <p className="font-mono text-xs text-muted-foreground leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
