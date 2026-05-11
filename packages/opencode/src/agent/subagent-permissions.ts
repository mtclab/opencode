import type { Permission } from "../permission"
import type { Agent } from "./agent"

/**
 * Build the `permission` ruleset for a subagent's session when it's spawned
 * via the task tool. Combines:
 *
 * 1. The parent **agent's** deny rules — Plan Mode and other agent-level
 *    restrictions live on the agent ruleset, not on the session, so a
 *    subagent that only inherited the parent SESSION's permission would
 *    silently bypass them. (#26514)
 * 2. The parent **session's** deny rules and external_directory rules —
 *    same forwarding the original code already did.
 * 3. The parent **session's** allow rules for MCP tools — subagents need
 *    explicit allow permissions to execute MCP tools (context7_resolve-library-id,
 *    matrix_matrix_read, etc.). Without this, subagents can see MCP tools in
 *    their tool list but get permission denied on execution. (#16491, #3808)
 * 4. Default `todowrite` and `task` denies if the subagent's own ruleset
 *    doesn't already permit them.
 */
export function deriveSubagentSessionPermission(input: {
  parentSessionPermission: Permission.Ruleset
  parentAgent: Agent.Info | undefined
  subagent: Agent.Info
}): Permission.Ruleset {
  const canTask = input.subagent.permission.some((rule) => rule.permission === "task")
  const canTodo = input.subagent.permission.some((rule) => rule.permission === "todowrite")
  const parentAgentDenies = input.parentAgent?.permission.filter((rule) => rule.action === "deny") ?? []
  const parentSessionMcpAllows = input.parentSessionPermission.filter(
    (rule) => rule.action === "allow" && rule.permission.includes("_"),
  )
  return [
    ...parentAgentDenies,
    ...input.parentSessionPermission.filter(
      (rule) => rule.permission === "external_directory" || rule.action === "deny",
    ),
    ...parentSessionMcpAllows,
    ...(canTodo ? [] : [{ permission: "todowrite" as const, pattern: "*" as const, action: "deny" as const }]),
    ...(canTask ? [] : [{ permission: "task" as const, pattern: "*" as const, action: "deny" as const }]),
  ]
}
