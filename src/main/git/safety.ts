/**
 * Git Safety System — protects user's codebase during agent execution.
 *
 * Flow:
 * 1. Before agent starts: create a branch `bld/task-{id}`
 * 2. Agent makes changes on the branch
 * 3. On approval: merge branch back (or user merges manually)
 * 4. On rejection: delete branch, restore original state
 *
 * Handles concurrent agents on the same repo via separate branches.
 */

import { execSync } from 'child_process'

export interface GitState {
  originalBranch: string
  taskBranch: string
  isClean: boolean
  hasUncommittedChanges: boolean
}

/**
 * Check if a directory is a git repo and get current state.
 */
export function getGitState(projectDir: string): GitState | null {
  try {
    const branch = git(projectDir, 'rev-parse --abbrev-ref HEAD').trim()
    const status = git(projectDir, 'status --porcelain')
    const isClean = status.trim() === ''

    return {
      originalBranch: branch,
      taskBranch: '',
      isClean,
      hasUncommittedChanges: !isClean
    }
  } catch {
    return null // Not a git repo
  }
}

/**
 * Prepare a safe branch for agent work.
 * Stashes any uncommitted changes, creates a new branch.
 */
export function prepareBranch(projectDir: string, taskId: string): {
  branch: string
  stashed: boolean
  originalBranch: string
} | null {
  const state = getGitState(projectDir)
  if (!state) return null

  const branchName = `bld/task-${taskId.slice(0, 8)}`
  let stashed = false

  try {
    // Stash uncommitted changes if any
    if (state.hasUncommittedChanges) {
      git(projectDir, 'stash push -m "bld: auto-stash before task"')
      stashed = true
    }

    // Create and checkout new branch from current HEAD
    git(projectDir, `checkout -b ${branchName}`)

    return {
      branch: branchName,
      stashed,
      originalBranch: state.originalBranch
    }
  } catch (err) {
    // Cleanup on failure
    try {
      git(projectDir, `checkout ${state.originalBranch}`)
      if (stashed) git(projectDir, 'stash pop')
    } catch {
      // Best effort cleanup
    }
    console.error('[git] prepareBranch failed:', err)
    return null
  }
}

/**
 * Commit agent changes on the task branch.
 */
export function commitAgentChanges(
  projectDir: string,
  taskId: string,
  prompt: string
): boolean {
  try {
    const status = git(projectDir, 'status --porcelain')
    if (status.trim() === '') return true // Nothing to commit

    git(projectDir, 'add -A')

    const message = `bld: ${prompt.slice(0, 72)}\n\nTask ID: ${taskId}\nAutomated commit by BLD agent.`
    // Use -m with the message, escaping quotes
    const escapedMessage = message.replace(/"/g, '\\"')
    git(projectDir, `commit -m "${escapedMessage}"`)

    return true
  } catch (err) {
    console.error('[git] commitAgentChanges failed:', err)
    return false
  }
}

/**
 * On approval: merge the task branch back into the original branch.
 */
export function mergeBranch(
  projectDir: string,
  taskBranch: string,
  originalBranch: string,
  stashed: boolean
): { success: boolean; error?: string } {
  try {
    // Switch back to original branch
    git(projectDir, `checkout ${originalBranch}`)

    // Merge task branch
    git(projectDir, `merge ${taskBranch} --no-ff -m "Merge ${taskBranch}"`)

    // Clean up task branch
    git(projectDir, `branch -d ${taskBranch}`)

    // Restore stashed changes if any
    if (stashed) {
      try {
        git(projectDir, 'stash pop')
      } catch {
        // Stash pop conflict — leave it for the user
        return { success: true, error: 'Merge succeeded but stash pop had conflicts. Run `git stash pop` manually.' }
      }
    }

    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { success: false, error: `Merge failed: ${message}` }
  }
}

/**
 * On rejection: delete the task branch and restore original state.
 */
export function rejectBranch(
  projectDir: string,
  taskBranch: string,
  originalBranch: string,
  stashed: boolean
): { success: boolean; error?: string } {
  try {
    // Switch back to original branch
    git(projectDir, `checkout ${originalBranch}`)

    // Force delete the task branch (discards all agent changes)
    git(projectDir, `branch -D ${taskBranch}`)

    // Restore stashed changes if any
    if (stashed) {
      try {
        git(projectDir, 'stash pop')
      } catch {
        return { success: true, error: 'Branch deleted but stash pop had conflicts.' }
      }
    }

    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    return { success: false, error: `Reject cleanup failed: ${message}` }
  }
}

/**
 * Get the diff for a task branch vs its parent.
 */
export function getBranchDiff(projectDir: string, taskBranch: string, originalBranch: string): string | null {
  try {
    return git(projectDir, `diff ${originalBranch}...${taskBranch}`)
  } catch {
    return null
  }
}

/**
 * List all active BLD branches in a repo.
 */
export function listBldBranches(projectDir: string): string[] {
  try {
    const output = git(projectDir, 'branch --list "bld/*"')
    return output
      .split('\n')
      .map((line) => line.trim().replace(/^\* /, ''))
      .filter(Boolean)
  } catch {
    return []
  }
}

/**
 * Execute a git command in the project directory.
 */
function git(cwd: string, command: string): string {
  return execSync(`git ${command}`, {
    cwd,
    encoding: 'utf-8',
    timeout: 15000,
    stdio: ['pipe', 'pipe', 'pipe']
  })
}
