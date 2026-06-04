import { useState } from "react";
import { useListSources, getListSourcesQueryKey, useCreateSource, useDeleteSource, useFetchSource, useFetchAllSources } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Plus, Trash2, RefreshCw, Download, Database } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { format } from "date-fns";
import { Badge } from "@/components/ui/badge";

export default function Sources() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const { data: sources, isLoading } = useListSources({
    query: {
      queryKey: getListSourcesQueryKey(),
    }
  });

  const createSource = useCreateSource();
  const deleteSource = useDeleteSource();
  const fetchSource = useFetchSource();
  const fetchAllSources = useFetchAllSources();

  const [newName, setNewName] = useState("");
  const [newUrl, setNewUrl] = useState("");
  const [newType, setNewType] = useState<"url" | "subscription" | "file">("subscription");

  const handleAddSource = () => {
    if (!newName || !newUrl) return;
    createSource.mutate(
      { data: { name: newName, url: newUrl, type: newType } },
      {
        onSuccess: () => {
          setNewName("");
          setNewUrl("");
          queryClient.invalidateQueries({ queryKey: getListSourcesQueryKey() });
          toast({ title: "Source added", description: "Successfully added new source" });
        },
        onError: (err: any) => {
          toast({ variant: "destructive", title: "Failed to add source", description: err.message });
        }
      }
    );
  };

  const handleDelete = (id: number) => {
    deleteSource.mutate(
      { id },
      {
        onSuccess: () => {
          queryClient.invalidateQueries({ queryKey: getListSourcesQueryKey() });
          toast({ title: "Source deleted" });
        }
      }
    );
  };

  const handleFetch = (id: number) => {
    fetchSource.mutate(
      { id },
      {
        onSuccess: (res) => {
          queryClient.invalidateQueries({ queryKey: getListSourcesQueryKey() });
          toast({
            title: "Fetch complete",
            description: `Found: ${res.found}, Added: ${res.added}, Duplicates: ${res.duplicates}`
          });
        },
        onError: (err: any) => {
          toast({ variant: "destructive", title: "Fetch failed", description: err.message });
        }
      }
    );
  };

  const handleFetchAll = () => {
    fetchAllSources.mutate(undefined, {
      onSuccess: (res) => {
        queryClient.invalidateQueries({ queryKey: getListSourcesQueryKey() });
        toast({
          title: "Fetch all complete",
          description: `Total Added: ${res.totalAdded}`
        });
      }
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold font-mono text-primary tracking-tight">/sources</h1>
          <p className="text-muted-foreground mt-2 font-mono text-sm">Manage configuration sources and subscriptions.</p>
        </div>
        <Button onClick={handleFetchAll} disabled={fetchAllSources.isPending} className="font-mono">
          <RefreshCw className={`mr-2 h-4 w-4 ${fetchAllSources.isPending ? "animate-spin" : ""}`} />
          FETCH_ALL
        </Button>
      </div>

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Add_New_Source</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-4 items-end">
            <div className="grid gap-2 flex-1">
              <label className="text-xs font-mono text-muted-foreground">NAME</label>
              <Input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="e.g. GitHub VLESS list"
                className="font-mono bg-background"
              />
            </div>
            <div className="grid gap-2 flex-[2]">
              <label className="text-xs font-mono text-muted-foreground">URL</label>
              <Input
                value={newUrl}
                onChange={(e) => setNewUrl(e.target.value)}
                placeholder="https://..."
                className="font-mono bg-background"
              />
            </div>
            <div className="grid gap-2 w-full md:w-48">
              <label className="text-xs font-mono text-muted-foreground">TYPE</label>
              <Select value={newType} onValueChange={(val: any) => setNewType(val)}>
                <SelectTrigger className="font-mono bg-background">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="subscription">Subscription</SelectItem>
                  <SelectItem value="url">Raw URL</SelectItem>
                  <SelectItem value="file">Local File</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button onClick={handleAddSource} disabled={createSource.isPending || !newName || !newUrl} className="w-full md:w-auto">
              <Plus className="h-4 w-4 mr-2" />
              ADD
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="text-lg font-mono">Managed_Sources</CardTitle>
          <CardDescription className="font-mono">Total sources: {sources?.length ?? 0}</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono">NAME</TableHead>
                <TableHead className="font-mono">TYPE</TableHead>
                <TableHead className="font-mono">CONFIGS</TableHead>
                <TableHead className="font-mono">LAST_FETCHED</TableHead>
                <TableHead className="text-right font-mono">ACTIONS</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-muted-foreground font-mono">
                    Loading sources...
                  </TableCell>
                </TableRow>
              ) : sources?.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center py-8 text-muted-foreground font-mono">
                    No sources added yet.
                  </TableCell>
                </TableRow>
              ) : (
                sources?.map((source) => (
                  <TableRow key={source.id} className="border-border hover:bg-accent/50">
                    <TableCell className="font-medium font-mono">
                      {source.name}
                      <div className="text-xs text-muted-foreground truncate max-w-[200px] md:max-w-md">
                        {source.url}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono rounded-sm bg-background">
                        {source.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">{source.configCount}</TableCell>
                    <TableCell className="font-mono text-sm text-muted-foreground">
                      {source.lastFetchedAt ? format(new Date(source.lastFetchedAt), "yyyy-MM-dd HH:mm:ss") : "Never"}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          className="font-mono h-8"
                          onClick={() => handleFetch(source.id)}
                          disabled={fetchSource.isPending && fetchSource.variables?.id === source.id}
                        >
                          <Download className="h-3.5 w-3.5 mr-1" />
                          FETCH
                        </Button>
                        <Button
                          variant="destructive"
                          size="sm"
                          className="h-8 w-8 p-0"
                          onClick={() => handleDelete(source.id)}
                          disabled={deleteSource.isPending}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}