import { useEffect, useMemo, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent } from "react";
import { APP_VERSION } from "@/lib/app-version";
import { DISCLAIMER, REPO_URL, buildNewIssueUrl } from "@/lib/constants";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Github, Bug, Info } from "lucide-react";
import { getSystemInfo } from "@/lib/api";
import type { SystemInfo } from "@/types";

const AboutPage = () => {
  const defaultIssueBody = useMemo(() => {
    const meta = [`App Version: v${APP_VERSION}`].join("\n");
    return `Describe the issue here...\n\n---\n${meta}`;
  }, []);

  const [showIssueModal, setShowIssueModal] = useState(false);
  const [issueTitle, setIssueTitle] = useState("");
  const [issueBody, setIssueBody] = useState(defaultIssueBody);
  const issueModalRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!showIssueModal) return;
    setIssueTitle("");
    // Build with base info first
    let base = [`App Version: v${APP_VERSION}`];

    // Try to include structured system info from backend
    (async () => {
      try {
        const res = await getSystemInfo();
        if (res?.success && res.data) {
          const sys: SystemInfo = res.data;
          const osLine = [
            `OS: ${sys.os}`,
            sys.version ? sys.version : undefined,
            sys.edition ? sys.edition : undefined,
            sys.arch ? `(${sys.arch})` : undefined,
          ]
            .filter(Boolean)
            .join(" ");
          const meta = [...base, osLine].filter(Boolean).join("\n");
          setIssueBody(`Describe the issue here...\n\n---\n${meta}`);
          return;
        }
      } catch {
        // ignore and fall back to base
      }
      const meta = base.join("\n");
      setIssueBody(`Describe the issue here...\n\n---\n${meta}`);
    })();
  }, [showIssueModal]);

  const handleOpenRepo = async () => {
    if (!REPO_URL) return;
    try {
      await openUrl(REPO_URL);
    } catch {
      // no-op
    }
  };

  const handleCreateIssue = async () => {
    const title = issueTitle.trim() || "Issue: ";
    const body = (issueBody.trim() || defaultIssueBody).trim();
    const url = buildNewIssueUrl(title, body);
    try {
      await openUrl(url);
      setShowIssueModal(false);
    } catch {
      // no-op
    }
  };

  const handleIssueModalKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      setShowIssueModal(false);
    }
  };

  const disclaimerBlocks = useMemo(() => {
    const lines = DISCLAIMER.split(/\r?\n/);
    type Block = { type: "paragraph"; content: string } | { type: "list"; content: string[] };
    const blocks: Block[] = [];
    let currentParagraph: string[] = [];
    let currentList: string[] = [];

    const flushParagraph = () => {
      if (currentParagraph.length) {
        blocks.push({ type: "paragraph", content: currentParagraph.join(" ") });
        currentParagraph = [];
      }
    };

    const flushList = () => {
      if (currentList.length) {
        blocks.push({ type: "list", content: currentList });
        currentList = [];
      }
    };

    for (const line of lines) {
      const trimmed = line.trim();

      if (!trimmed) {
        flushParagraph();
        flushList();
        continue;
      }

      if (trimmed.startsWith("- ")) {
        flushParagraph();
        currentList.push(trimmed.slice(2).trim());
      } else {
        flushList();
        currentParagraph.push(trimmed);
      }
    }

    flushParagraph();
    flushList();

    return blocks;
  }, []);

  return (
    <div className="max-w-full mx-auto space-y-6">
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
          <Info className="h-5 w-5" /> About
        </h1>
        <p className="text-muted-foreground">Version info, links, and disclaimer.</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-lg">
            <Info className="h-4 w-4" /> Application
          </CardTitle>
          <CardDescription>Basic information about this app</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">Version</div>
            <code className="text-sm">v{APP_VERSION}</code>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm text-muted-foreground">Repository</div>
            <Button size="sm" variant="secondary" onClick={handleOpenRepo} disabled={!REPO_URL}>
              <Github className="h-4 w-4 mr-1" /> Open GitHub
            </Button>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm text-muted-foreground">Issues</div>
            <Button size="sm" onClick={() => setShowIssueModal(true)}>
              <Bug className="h-4 w-4 mr-1" /> Report Bug
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Disclaimer</CardTitle>
          <CardDescription>Important information about this product</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {disclaimerBlocks.map((block, index) => {
            if (block.type === "paragraph") {
              return (
                <p key={`paragraph-${index}`} className="text-sm leading-6">
                  {block.content}
                </p>
              );
            }

            return (
              <ul key={`list-${index}`} className="ml-5 list-disc space-y-2 text-sm leading-6">
                {block.content.map((item, itemIndex) => (
                  <li key={itemIndex}>{item}</li>
                ))}
              </ul>
            );
          })}
        </CardContent>
      </Card>

      {showIssueModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div
            className="fixed inset-0 bg-foreground/40"
            onClick={() => setShowIssueModal(false)}
          />
          <div className="relative z-10 flex min-h-full items-center justify-center px-4 py-10">
            <Card
              ref={issueModalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="issueModal-title"
              aria-describedby="issueModal-description"
              tabIndex={-1}
              onKeyDown={handleIssueModalKeyDown}
              className="w-full max-w-4xl max-h-[90vh] overflow-auto border-border shadow-2xl outline-none bg-background text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
            >
              <CardHeader className="space-y-1">
                <CardTitle id="issueModal-title" className="flex items-center gap-2 text-xl">
                  <Bug className="h-5 w-5" /> Report a Bug
                </CardTitle>
                <CardDescription id="issueModal-description">
                  Pre-fill a GitHub issue with environment details to help us reproduce and fix problems quickly.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="issueTitle">Title</Label>
                  <Input
                    id="issueTitle"
                    placeholder="Concise summary"
                    value={issueTitle}
                    onChange={(event) => setIssueTitle(event.target.value)}
                    className="bg-background"
                    autoFocus
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="issueBody">Description</Label>
                  <textarea
                    id="issueBody"
                    name="issueBody"
                    placeholder="Describe the issue in detail"
                    className="flex min-h-[16rem] w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm shadow-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
                    value={issueBody}
                    onChange={(event) => setIssueBody(event.target.value)}
                  />
                </div>
              </CardContent>
              <CardFooter className="flex-col gap-4 p-4 pt-4 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-xs text-muted-foreground">
                  When you continue, GitHub opens in your browser with these details pre-filled. You can edit before submitting.
                </p>
                <div className="flex w-full justify-end gap-2 sm:w-auto">
                  <Button variant="secondary" onClick={() => setShowIssueModal(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreateIssue}>
                    <Bug className="h-4 w-4 mr-1" /> Create Issue
                  </Button>
                </div>
              </CardFooter>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
};

export default AboutPage;
