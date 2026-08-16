import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, test } from "bun:test";
import {
  checkScanPublicationInternal,
  type CheckScanPublicationDependencies,
  type CheckScanPublicationOptions,
} from "../src/publish.js";
import type { PreparedScanPublication } from "../src/publication.js";

const OPTIONS: CheckScanPublicationOptions = {
  destination: "linear",
  teamId: "team-example",
  projectId: "project-example",
};
const PUBLICATION: PreparedScanPublication = {
  scanId: "scan-example",
  uploadId: "scan-example",
  scanDirectory: join(tmpdir(), "completed-scan"),
  destination: {
    type: "linear",
    teamId: "team-example",
    projectId: "project-example",
  },
  issues: [1, 2].map((number) => ({
    findingId: `finding-${number}`,
    occurrenceId: `occurrence-${number}`,
    title: `Synthetic finding ${number}`,
    description: "Synthetic description that must stay local during preflight.",
  })),
};
const RECORDED = {
  findingId: "finding-1",
  occurrenceId: "occurrence-1",
  issueIdentifier: "EXAMPLE-101",
};
type ReadClient = ReturnType<
  NonNullable<CheckScanPublicationDependencies["linearClient"]>
>;

function dependencies(
  overrides: Partial<CheckScanPublicationDependencies> = {},
): CheckScanPublicationDependencies {
  return {
    environment: {},
    prepare: async () => PUBLICATION,
    inspectPublicationStore: async (publication) => {
      expect(publication).toBe(PUBLICATION);
      return [RECORDED];
    },
    ...overrides,
  };
}

function readClient(
  calls: unknown[],
  options: {
    teams?: readonly string[];
    active?: boolean;
    archivedProject?: boolean;
    retiredTeam?: boolean;
  } = {},
): ReadClient {
  return {
    get viewer() {
      calls.push("viewer");
      return Promise.resolve({ id: "viewer-example" });
    },
    team: async (id: string) => {
      calls.push(["team", id]);
      return {
        id: "canonical-team",
        retiredAt: options.retiredTeam ? new Date(0) : undefined,
      };
    },
    project: async (id: string) => {
      calls.push(["project", id]);
      return {
        archivedAt: options.archivedProject ? new Date(0) : undefined,
        teams: async (variables: unknown) => {
          calls.push(["project.teams", variables]);
          return {
            nodes: (options.teams ?? ["canonical-team"]).map((team) => ({
              id: team,
            })),
          };
        },
      };
    },
    users: async (variables: unknown) => {
      calls.push(["users", variables]);
      return { nodes: [{ id: "assignee-example" }] };
    },
    user: async (id: string) => {
      calls.push(["user", id]);
      return { id, active: options.active ?? true };
    },
    createIssue: () => {
      throw new Error("Preflight must not create issues.");
    },
  } as unknown as ReadClient;
}

describe("read-only publication preflight", () => {
  test("reports local history without claiming connected-app access", async () => {
    const result = await checkScanPublicationInternal(
      "scan",
      OPTIONS,
      dependencies({
        linearClient: () => {
          throw new Error("No remote client should be constructed.");
        },
      }),
    );
    expect(result).toEqual({
      scanId: PUBLICATION.scanId,
      destination: PUBLICATION.destination,
      recorded: [RECORDED],
      counts: { findings: 2, recorded: 1, pending: 1 },
      access: {
        transport: "connected-app",
        authentication: "not-checked",
        team: "not-checked",
        project: "not-checked",
        assignee: "not-requested",
        issueCreation: "not-tested",
      },
    });
    expect(JSON.stringify(result)).not.toContain(
      PUBLICATION.issues[0]!.description,
    );
  });

  test("uses only read queries for direct API access and omits credentials and identities", async () => {
    const calls: unknown[] = [];
    const key = "lin_api_SYNTHETIC_PREFLIGHT_KEY";
    const assignee = "teammate@example.com";
    const signal = new AbortController().signal;
    const result = await checkScanPublicationInternal(
      "scan",
      { ...OPTIONS, linearApiKey: key, assigneeId: assignee, signal },
      dependencies({
        environment: { CODEX_SECURITY_LINEAR_API_KEY: "environment-key" },
        linearClient: (configuration) => {
          expect(configuration).toEqual({
            apiKey: key,
            redirect: "error",
            signal,
          });
          return readClient(calls);
        },
      }),
    );
    expect(calls).toEqual([
      "viewer",
      ["team", "team-example"],
      ["project", "project-example"],
      ["project.teams", { filter: { id: { eq: "canonical-team" } }, first: 1 }],
      ["users", { filter: { email: { eqIgnoreCase: assignee } }, first: 2 }],
      ["user", "assignee-example"],
    ]);
    expect(result.access).toEqual({
      transport: "linear-api",
      authentication: "verified",
      team: "verified",
      project: "verified",
      assignee: "verified",
      issueCreation: "not-tested",
    });
    for (const privateValue of [
      key,
      assignee,
      "viewer-example",
      "assignee-example",
      PUBLICATION.issues[0]!.description,
    ]) {
      expect(JSON.stringify(result)).not.toContain(privateValue);
    }
  });

  test("checks team-only destinations without requesting a project or assignee", async () => {
    const calls: unknown[] = [];
    const publication = {
      ...PUBLICATION,
      destination: { type: "linear" as const, teamId: OPTIONS.teamId },
    };
    const result = await checkScanPublicationInternal(
      "scan",
      { destination: "linear", teamId: OPTIONS.teamId },
      dependencies({
        environment: { CODEX_SECURITY_LINEAR_API_KEY: "environment-key" },
        prepare: async () => publication,
        inspectPublicationStore: async () => [],
        linearClient: () => readClient(calls),
      }),
    );
    expect(calls).toEqual(["viewer", ["team", "team-example"]]);
    expect(result.access.project).toBe("not-requested");
    expect(result.access.assignee).toBe("not-requested");
    expect(result.access.issueCreation).toBe("not-tested");
  });

  test("rejects unavailable or incompatible destinations and inactive assignees", async () => {
    for (const [clientOptions, message] of [
      [{ teams: [] }, /does not belong/u],
      [{ archivedProject: true }, /project is archived/u],
      [{ retiredTeam: true }, /team is archived or retired/u],
      [{ active: false }, /assignee is inactive/u],
    ] as const) {
      await expect(
        checkScanPublicationInternal(
          "scan",
          {
            ...OPTIONS,
            linearApiKey: "synthetic-key",
            assigneeId: "assignee-example",
          },
          dependencies({
            linearClient: () => readClient([], clientOptions),
          }),
        ),
      ).rejects.toThrow(message);
    }
  });

  test("verifies local history before contacting Linear and preserves cancellation", async () => {
    const calls: unknown[] = [];
    await expect(
      checkScanPublicationInternal(
        "scan",
        { ...OPTIONS, linearApiKey: "synthetic-key" },
        dependencies({
          inspectPublicationStore: async () => {
            throw new Error("Missing local history.");
          },
          linearClient: () => readClient(calls),
        }),
      ),
    ).rejects.toThrow("Missing local history.");
    const controller = new AbortController();
    controller.abort(new Error("Canceled preflight."));
    await expect(
      checkScanPublicationInternal(
        "scan",
        { ...OPTIONS, signal: controller.signal },
        dependencies({
          prepare: async () => {
            throw new Error("Must not prepare after cancellation.");
          },
        }),
      ),
    ).rejects.toThrow("Canceled preflight.");
    expect(calls).toEqual([]);
  });

  test("does not echo provider response data on an access failure", async () => {
    const key = "lin_api_SYNTHETIC_PRIVATE_KEY";
    const client = readClient([]);
    client.team = (() => {
      throw new Error(`Provider response included ${key}`);
    }) as ReadClient["team"];
    await expect(
      checkScanPublicationInternal(
        "scan",
        { ...OPTIONS, linearApiKey: key },
        dependencies({ linearClient: () => client }),
      ),
    ).rejects.toThrow(
      "Could not verify Linear team access. Check the API key and publication destination.",
    );
  });
});
