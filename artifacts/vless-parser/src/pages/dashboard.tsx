import { useGetConfigStats, getGetConfigStatsQueryKey, useGetCheckerStatus, getGetCheckerStatusQueryKey } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Activity, ServerCrash, ShieldCheck, Server, AlertCircle, Shield, CloudRain } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

interface TPSUStats {
  version: string;
  blocked_asns: number;
  bad_fingerprints: number;
  good_fingerprints: string[];
  experimental_fp: string[];
  safe_front_sni: number;
  blacklist_sni: number;
  stats_json: Record<string, unknown> | null;
}

const fetchTpsu = async (): Promise<TPSUStats> => {
  const res = await fetch("/api/tpsu");
  if (!res.ok) throw new Error("TPSU endpoint error");
  return res.json();
};

export default function Dashboard() {
  const { data: checkerStatus } = useGetCheckerStatus({
    query: {
      queryKey: getGetCheckerStatusQueryKey(),
      refetchInterval: (query) => (query.state.data?.running ? 2000 : false),
    }
  });

  const { data: stats } = useGetConfigStats({
    query: {
      queryKey: getGetConfigStatsQueryKey(),
      refetchInterval: 5000,
    }
  });

  const { data: tpsu } = useQuery<TPSUStats>({
    queryKey: ["tpsu"],
    queryFn: fetchTpsu,
    refetchInterval: 30000,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/dashboard</h1>
        <p className="text-muted-foreground mt-2 font-mono text-sm">System status and configuration overview.</p>
      </div>

      {checkerStatus?.running && (
        <Card className="border-primary/50 bg-primary/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-mono flex items-center gap-2 text-primary">
              <Activity className="h-5 w-5 animate-pulse" />
              CHECKER_JOB_RUNNING
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <div className="flex justify-between text-sm font-mono">
                <span>Progress: {checkerStatus.checked} / {checkerStatus.total}</span>
                <span>{Math.round((checkerStatus.checked / (checkerStatus.total || 1)) * 100)}%</span>
              </div>
              <Progress value={(checkerStatus.checked / (checkerStatus.total || 1)) * 100} className="h-2" />
              <div className="flex gap-4 text-xs font-mono mt-2 text-muted-foreground">
                <span className="text-green-400">Working: {checkerStatus.working}</span>
                <span className="text-destructive">Failed: {checkerStatus.failed}</span>
                <span>Level: {checkerStatus.level}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Configs"
          value={stats?.total ?? 0}
          icon={Server}
          description="Parsed VLESS URIs"
        />
        <StatCard
          title="TCP OK"
          value={stats?.tcpOk ?? 0}
          icon={Activity}
          description="Basic connectivity"
          valueClass="text-blue-400"
        />
        <StatCard
          title="TLS OK"
          value={stats?.tlsOk ?? 0}
          icon={ShieldCheck}
          description="Handshake successful"
          valueClass="text-green-400"
        />
        <StatCard
          title="Failed"
          value={stats?.failed ?? 0}
          icon={ServerCrash}
          description="Dead proxies"
          valueClass="text-destructive"
        />
      </div>
      
      {tpsu && (
        <Card className="bg-card border-border border-primary/30">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-mono flex items-center gap-2 text-primary">
              <Shield className="h-5 w-5" />
              TPSU_BYPASS :: {tpsu.version}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-4 text-sm font-mono">
              <div>
                <span className="text-muted-foreground">Blocked ASNs</span>
                <div className="text-xl font-bold text-destructive">{tpsu.blocked_asns}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Bad Fingerprints</span>
                <div className="text-xl font-bold text-destructive">{tpsu.bad_fingerprints}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Safe Front SNI</span>
                <div className="text-xl font-bold text-green-400">{tpsu.safe_front_sni}</div>
              </div>
            </div>
            <div className="flex gap-1 mt-3 flex-wrap text-xs">
              <span className="text-muted-foreground">Good FP:</span>
              {tpsu.good_fingerprints.map((fp) => (
                <code key={fp} className="bg-green-900/30 text-green-300 px-1 rounded">{fp}</code>
              ))}
              <span className="text-muted-foreground ml-2">Experimental:</span>
              {tpsu.experimental_fp.map((fp) => (
                <code key={fp} className="bg-blue-900/30 text-blue-300 px-1 rounded">{fp}</code>
              ))}
            </div>
            {tpsu.stats_json && (
              <div className="flex gap-3 mt-3 text-xs text-muted-foreground font-mono border-t border-border pt-2">
                <CloudRain className="h-3 w-3 mt-0.5 text-blue-400" />
                <span>CF IPs: {String((tpsu.stats_json as any).cloudflare_ips ?? "N/A")}</span>
                <span>Success: {String((tpsu.stats_json as any).success_rate ?? "N/A")}%</span>
                <span>Avg speed: {String((tpsu.stats_json as any).avg_speed_mbps ?? "N/A")} Mbps</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
         <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="text-lg font-mono">Status_Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <DistributionRow label="Unchecked" count={stats?.unchecked ?? 0} total={stats?.total ?? 0} color="bg-muted-foreground" />
              <DistributionRow label="TCP OK" count={stats?.tcpOk ?? 0} total={stats?.total ?? 0} color="bg-blue-400" />
              <DistributionRow label="TLS OK" count={stats?.tlsOk ?? 0} total={stats?.total ?? 0} color="bg-green-400" />
              <DistributionRow label="HTTP OK" count={stats?.httpOk ?? 0} total={stats?.total ?? 0} color="bg-emerald-400" />
              <DistributionRow label="Failed" count={stats?.failed ?? 0} total={stats?.total ?? 0} color="bg-destructive" />
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, description, valueClass = "text-foreground" }: any) {
  return (
    <Card className="bg-card border-border">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium font-mono text-muted-foreground">
          {title}
        </CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className={`text-3xl font-bold font-mono ${valueClass}`}>{value}</div>
        <p className="text-xs text-muted-foreground mt-1 font-mono">
          {description}
        </p>
      </CardContent>
    </Card>
  );
}

function DistributionRow({ label, count, total, color }: any) {
  const percentage = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm font-mono">
        <span>{label}</span>
        <span className="text-muted-foreground">{count} ({percentage.toFixed(1)}%)</span>
      </div>
      <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${percentage}%` }} />
      </div>
    </div>
  );
}