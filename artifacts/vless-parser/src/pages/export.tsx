import { useState } from "react";
import { useExportConfigs } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Download, Copy, Check, FileCode, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Export() {
  const { toast } = useToast();
  const [format, setFormat] = useState<"singbox" | "xray" | "raw">("singbox");
  const [level, setLevel] = useState<"tcp" | "tls" | "http">("tcp");
  const [limit, setLimit] = useState("100");
  const [copied, setCopied] = useState(false);
  const [result, setResult] = useState<{ format: string; count: number; content: string } | null>(null);

  const exportMutation = useExportConfigs({
    mutation: {
      onSuccess: (data) => {
        setResult(data);
        toast({ title: "Export ready", description: `${data.count} configs exported in ${data.format} format` });
      },
      onError: () => {
        toast({ title: "Error", description: "Export failed", variant: "destructive" });
      },
    },
  });

  const handleExport = () => {
    setResult(null);
    exportMutation.mutate({
      data: {
        format,
        level,
        limit: parseInt(limit, 10),
      },
    });
  };

  const handleCopy = async () => {
    if (!result) return;
    await navigator.clipboard.writeText(result.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast({ title: "Copied", description: "Content copied to clipboard" });
  };

  const handleDownload = () => {
    if (!result) return;
    const ext = format === "raw" ? "txt" : "json";
    const filename = `vless-${format}-${level}-${Date.now()}.${ext}`;
    const blob = new Blob([result.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const formatIcons = {
    singbox: <FileCode className="w-4 h-4" />,
    xray: <FileCode className="w-4 h-4" />,
    raw: <FileText className="w-4 h-4" />,
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/export</h1>
        <p className="text-muted-foreground mt-2 font-mono text-sm">Export working configs in Sing-Box, Xray, or raw URI format.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">Export Settings</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Format</label>
              <Select value={format} onValueChange={(v) => setFormat(v as "singbox" | "xray" | "raw")}>
                <SelectTrigger data-testid="select-format" className="font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="singbox">Sing-Box JSON</SelectItem>
                  <SelectItem value="xray">Xray JSON</SelectItem>
                  <SelectItem value="raw">Raw VLESS URIs</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Min Check Level</label>
              <Select value={level} onValueChange={(v) => setLevel(v as "tcp" | "tls" | "http")}>
                <SelectTrigger data-testid="select-export-level" className="font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tcp">TCP OK</SelectItem>
                  <SelectItem value="tls">TLS OK</SelectItem>
                  <SelectItem value="http">HTTP OK</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Limit</label>
              <Select value={limit} onValueChange={setLimit}>
                <SelectTrigger data-testid="select-limit" className="font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {[25, 50, 100, 200, 500, 1000].map((n) => (
                    <SelectItem key={n} value={String(n)}>{n} configs</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button
              data-testid="button-export"
              className="w-full font-mono"
              onClick={handleExport}
              disabled={exportMutation.isPending}
            >
              {formatIcons[format]}
              <span className="ml-2">{exportMutation.isPending ? "Exporting..." : "Generate Export"}</span>
            </Button>
          </CardContent>
        </Card>

        <div className="md:col-span-2 space-y-4">
          {result && (
            <Card className="border-primary/40">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">Output</CardTitle>
                    <Badge variant="outline" className="font-mono text-primary border-primary/50">
                      {result.count} configs
                    </Badge>
                    <Badge variant="outline" className="font-mono text-muted-foreground">
                      {result.format.toUpperCase()}
                    </Badge>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      data-testid="button-copy"
                      size="sm"
                      variant="outline"
                      className="font-mono text-xs"
                      onClick={handleCopy}
                    >
                      {copied ? <Check className="w-3 h-3 mr-1 text-green-400" /> : <Copy className="w-3 h-3 mr-1" />}
                      {copied ? "Copied" : "Copy"}
                    </Button>
                    <Button
                      data-testid="button-download"
                      size="sm"
                      variant="outline"
                      className="font-mono text-xs"
                      onClick={handleDownload}
                    >
                      <Download className="w-3 h-3 mr-1" />
                      Download
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <pre
                  data-testid="text-export-content"
                  className="bg-muted/30 border border-border/50 rounded-md p-4 text-xs font-mono text-muted-foreground overflow-auto max-h-[500px] whitespace-pre-wrap break-all"
                >
                  {result.content}
                </pre>
              </CardContent>
            </Card>
          )}

          {!result && (
            <Card className="border-border/50 border-dashed">
              <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                <Download className="w-8 h-8 text-muted-foreground/40 mb-4" />
                <p className="font-mono text-sm text-muted-foreground">Configure export settings and click Generate.</p>
                <p className="font-mono text-xs text-muted-foreground/60 mt-2">Only configs that passed the selected check level will be included.</p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
