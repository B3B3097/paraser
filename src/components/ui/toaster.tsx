import { useToast } from "@/hooks/use-toast";
import { X } from "lucide-react";

export function Toaster() {
  const { toasts, dismiss } = useToast();

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-md w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto flex items-start justify-between gap-3 p-4 rounded-md border shadow-lg font-mono text-sm transition-all duration-200 ${
            t.variant === "destructive"
              ? "bg-destructive text-destructive-foreground border-destructive"
              : "bg-card text-card-foreground border-border"
          }`}
        >
          <div className="flex-1">
            {t.title && <div className="font-semibold text-sm">{t.title}</div>}
            {t.description && (
              <div className="text-xs text-muted-foreground mt-1">
                {t.description}
              </div>
            )}
          </div>
          <button
            onClick={() => dismiss(t.id)}
            className="p-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      ))}
    </div>
  );
}
