import {
  CodexSecurity,
  DiffTarget,
  estimateScanCost,
  type ScanCost,
  type ScanOptions,
  type ScanResult,
} from "@openai/codex-security";

const options: ScanOptions = {
  target: DiffTarget.refs({ base: "HEAD~1" }),
  onProgress(progress) {
    const completed: number = progress.filesCompleted;
    void completed;
  },
};

export async function scan(repository: string): Promise<ScanResult> {
  const client = new CodexSecurity();
  try {
    return await client.run(repository, options);
  } finally {
    await client.close();
  }
}

export const cost: ScanCost | null = estimateScanCost("gpt-5.6-sol", {
  input_tokens: 10,
  output_tokens: 2,
});

// @ts-expect-error Dependency injection is internal, not a public constructor overload.
new CodexSecurity({}, {}, { surface: "sdk" });
