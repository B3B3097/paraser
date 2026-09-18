import { useState, useEffect } from "react";
import { useExportConfigs } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Download, Copy, Check, FileCode, FileText, Shield, Zap, Globe, RefreshCw } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface SubscriptionItem {
  id: string;
  name: string;
  description: string;
  file: string;
  fileBase64: string;
  rawUrl: string;
  base64Url: string;
  count: number;
  bsCount: number;
}

export default function Export() {
  const { toast } = useToast();
  const [format, setFormat] = useState<"singbox" | "xray" | "raw">("singbox");
  const [level, setLevel] = useState<"tcp" | "tls" | "http">("tcp");
  const [limit, setLimit] = useState("100");
  const [copied, setCopied] = useState(false);
  const [copiedSubId, setCopiedSubId] = useState<string | null>(null);
  const [result, setResult] = useState<{ format: string; count: number; content: string } | null>(null);

  const [subscriptions, setSubscriptions] = useState<SubscriptionItem[]>([
    {
      id: "250-20bs",
      name: "250 Конфигов (20 БС + 230 Интернет)",
      description: "Ровно 250 проверенных серверов: 20 для Белых Списков РФ (VK, Yandex, X5, OK, LTE/5G) + 230 скоростных зарубежных серверов",
      file: "sub_250_20bs.txt",
      fileBase64: "sub_250_20bs_base64.txt",
      rawUrl: "/sub/sub_250_20bs.txt",
      base64Url: "/sub/sub_250_20bs_base64.txt",
      count: 250,
      bsCount: 20,
    },
    {
      id: "bs-top-ping",
      name: "BS Top Ping (БС Топ по пингу)",
      description: "Конфиги для обхода белых списков РФ, отсортированные по наименьшей задержке (минимальный пинг)",
      file: "sub_bs_top_ping.txt",
      fileBase64: "sub_bs_top_ping_base64.txt",
      rawUrl: "/sub/sub_bs_top_ping.txt",
      base64Url: "/sub/sub_bs_top_ping_base64.txt",
      count: 200,
      bsCount: 200,
    },
    {
      id: "bs-all",
      name: "BS Все (Все конфиги белых списков)",
      description: "Полный массив всех доступных рабочих конфигураций для белых списков и обхода блокировок",
      file: "sub_bs_all.txt",
      fileBase64: "sub_bs_all_base64.txt",
      rawUrl: "/sub/sub_bs_all.txt",
      base64Url: "/sub/sub_bs_all_base64.txt",
      count: 3046,
      bsCount: 3046,
    },
  ]);
  const [isGenerating, setIsGenerating] = useState(false);

  const fetchSubscriptions = async () => {
    try {
      const res = await fetch("/api/subscriptions");
      if (res.ok) {
        const data = await res.json();
        if (data.subscriptions) {
          setSubscriptions(data.subscriptions);
        }
      }
    } catch {
      // fallback to state
    }
  };

  useEffect(() => {
    fetchSubscriptions();
  }, []);

  const handleRegenerateSubs = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch("/api/subscriptions/generate", { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        toast({ title: "Успех", description: data.message || "Подписки обновлены" });
        await fetchSubscriptions();
      } else {
        toast({ title: "Ошибка", description: data.error || "Сбой генерации", variant: "destructive" });
      }
    } catch (e: any) {
      toast({ title: "Ошибка", description: e.message, variant: "destructive" });
    } finally {
      setIsGenerating(false);
    }
  };

  const copySubUrl = async (pathUrl: string, key: string) => {
    const fullUrl = `${window.location.origin}${pathUrl}`;
    try {
      await navigator.clipboard.writeText(fullUrl);
      setCopiedSubId(key);
      setTimeout(() => setCopiedSubId(null), 2000);
      toast({ title: "Скопировано в буфер обмена", description: fullUrl });
    } catch {
      toast({ title: "Не удалось скопировать", description: fullUrl });
    }
  };

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
    try {
      await navigator.clipboard.writeText(result.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
      toast({ title: "Copied", description: "Content copied to clipboard" });
    } catch {
      toast({ title: "Notice", description: "Clipboard access failed. Select text manually." });
    }
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
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/export &amp; subscriptions</h1>
        <p className="text-muted-foreground mt-2 font-mono text-sm">
          Готовые подписки для v2rayNG, Happ, NekoBox, Hiddify и настраиваемый экспорт в Sing-Box / Xray.
        </p>
      </div>

      {/* 3 Новые Подписки (БС, Top Ping, 250/20) */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold font-mono tracking-tight text-foreground flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" />
              3 Готовые Подписки (Белые списки РФ &amp; Vlessforu)
            </h2>
            <p className="text-xs text-muted-foreground mt-1">
              Проверка на белый список построена на основе базы российских доменов (VK, Yandex, X5, OK, Госуслуги) и мобильных обходов LTE/5G.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRegenerateSubs}
            disabled={isGenerating}
            className="font-mono text-xs self-start sm:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${isGenerating ? "animate-spin" : ""}`} />
            {isGenerating ? "Генерация..." : "Обновить подписки"}
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {subscriptions.map((sub) => {
            const is250 = sub.id === "250-20bs";
            const isTopPing = sub.id === "bs-top-ping";
            const icon = is250 ? (
              <Globe className="w-4 h-4 text-emerald-400" />
            ) : isTopPing ? (
              <Zap className="w-4 h-4 text-amber-400" />
            ) : (
              <Shield className="w-4 h-4 text-blue-400" />
            );

            return (
              <Card key={sub.id} className="border-border/60 flex flex-col justify-between hover:border-primary/50 transition-colors">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      {icon}
                      <CardTitle className="font-mono text-sm">{sub.name}</CardTitle>
                    </div>
                    <Badge variant="outline" className="font-mono text-xs border-primary/40 text-primary">
                      {sub.count} серверов
                    </Badge>
                  </div>
                  <CardDescription className="text-xs leading-relaxed text-muted-foreground">
                    {sub.description}
                  </CardDescription>
                </CardHeader>

                <CardContent className="pt-0 space-y-3">
                  <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
                    <Badge variant="secondary" className="px-2 py-0.5">
                      {sub.bsCount} БС
                    </Badge>
                    {is250 && (
                      <Badge variant="secondary" className="px-2 py-0.5">
                        230 Скоростных
                      </Badge>
                    )}
                    {isTopPing && (
                      <Badge variant="secondary" className="px-2 py-0.5">
                        Min Latency
                      </Badge>
                    )}
                  </div>

                  <div className="space-y-2 pt-2 border-t border-border/40">
                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-muted-foreground">URL подписки (Raw):</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs font-mono"
                        onClick={() => copySubUrl(sub.rawUrl, `${sub.id}-raw`)}
                      >
                        {copiedSubId === `${sub.id}-raw` ? (
                          <Check className="w-3 h-3 mr-1 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 mr-1" />
                        )}
                        {copiedSubId === `${sub.id}-raw` ? "Скопировано" : "Копировать"}
                      </Button>
                    </div>

                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-muted-foreground">Base64 (v2rayNG/Happ):</span>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs font-mono"
                        onClick={() => copySubUrl(sub.base64Url, `${sub.id}-b64`)}
                      >
                        {copiedSubId === `${sub.id}-b64` ? (
                          <Check className="w-3 h-3 mr-1 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 mr-1" />
                        )}
                        {copiedSubId === `${sub.id}-b64` ? "Скопировано" : "Копировать"}
                      </Button>
                    </div>

                    <div className="pt-1">
                      <a href={sub.rawUrl} download={sub.file} className="block w-full">
                        <Button variant="outline" size="sm" className="w-full h-8 font-mono text-xs">
                          <Download className="w-3 h-3 mr-1.5" />
                          Скачать .txt
                        </Button>
                      </a>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Пользовательский Экспорт (Sing-box, Xray, Raw) */}
      <div className="pt-4 border-t border-border/40">
        <h2 className="text-lg font-semibold font-mono tracking-tight text-foreground mb-4">
          Пользовательский экспорт конфигураций
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">
                Параметры экспорта
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Формат</label>
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
                <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">
                  Мин. уровень проверки
                </label>
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
                <label className="font-mono text-xs text-muted-foreground uppercase tracking-wider">Лимит</label>
                <Select value={limit} onValueChange={setLimit}>
                  <SelectTrigger data-testid="select-limit" className="font-mono">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {[25, 50, 100, 200, 500, 1000].map((n) => (
                      <SelectItem key={n} value={String(n)}>
                        {n} configs
                      </SelectItem>
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
                      <CardTitle className="font-mono text-sm text-muted-foreground uppercase tracking-widest">
                        Output
                      </CardTitle>
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
                  <p className="font-mono text-xs text-muted-foreground/60 mt-2">
                    Only configs that passed the selected check level will be included.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
