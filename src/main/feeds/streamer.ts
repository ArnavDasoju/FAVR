/**
 * Live Feed Streamer — captures periodic screenshots and streams them to agent cards.
 *
 * During agent execution:
 *   - Terminal feed streams via agent:output (already wired)
 * During validation:
 *   - Captures screenshots of dev server at interval (~2fps for active, less for idle)
 *   - Streams frames via agent:frame as base64 data URIs
 * On completion:
 *   - Sends final validation screenshot with pass/fail badge
 */

import { BrowserWindow } from 'electron'
import { captureScreenshot, isServerReachable } from '../validation/screenshot'

interface FeedSession {
  agentId: string
  devServerUrl: string
  interval: ReturnType<typeof setInterval> | null
  active: boolean
}

class FeedStreamer {
  private sessions: Map<string, FeedSession> = new Map()

  /**
   * Start streaming screenshots from a dev server for an agent.
   * Called when agent enters validation phase and dev server is available.
   */
  async startStreaming(agentId: string, devServerUrl: string, intervalMs = 500): Promise<void> {
    // Stop any existing session for this agent
    this.stopStreaming(agentId)

    // Check if server is reachable first
    const reachable = await isServerReachable(devServerUrl)
    if (!reachable) {
      console.log(`[feed] Dev server not reachable at ${devServerUrl}, skipping live feed`)
      return
    }

    const session: FeedSession = {
      agentId,
      devServerUrl,
      interval: null,
      active: true
    }

    this.sessions.set(agentId, session)

    // Capture initial frame
    await this.captureAndEmit(session)

    // Start periodic capture
    session.interval = setInterval(async () => {
      if (!session.active) return
      await this.captureAndEmit(session)
    }, intervalMs)

    console.log(`[feed] Started streaming for agent ${agentId} at ${devServerUrl}`)
  }

  /**
   * Stop streaming for an agent.
   */
  stopStreaming(agentId: string): void {
    const session = this.sessions.get(agentId)
    if (!session) return

    session.active = false
    if (session.interval) {
      clearInterval(session.interval)
      session.interval = null
    }
    this.sessions.delete(agentId)
    console.log(`[feed] Stopped streaming for agent ${agentId}`)
  }

  /**
   * Capture a single frame and send the final validation screenshot.
   */
  async captureFinalFrame(agentId: string, devServerUrl: string): Promise<string | null> {
    const result = await captureScreenshot(devServerUrl, { waitFor: 1000 })
    if (!result) return null

    const dataUri = `data:image/png;base64,${result.base64}`

    // Send as both frame and validation screenshot
    this.emit('agent:frame', { agentId, frame: dataUri })
    this.emit('agent:validationScreenshot', { agentId, screenshot: dataUri })

    return dataUri
  }

  /**
   * Stop all active sessions.
   */
  stopAll(): void {
    for (const agentId of this.sessions.keys()) {
      this.stopStreaming(agentId)
    }
  }

  private async captureAndEmit(session: FeedSession): Promise<void> {
    if (!session.active) return

    try {
      const result = await captureScreenshot(session.devServerUrl, {
        waitFor: 0, // No extra wait for streaming frames
        width: 640,
        height: 400
      })

      if (result && session.active) {
        const dataUri = `data:image/png;base64,${result.base64}`
        this.emit('agent:frame', {
          agentId: session.agentId,
          frame: dataUri
        })
      }
    } catch {
      // Frame capture failed — skip this frame, try next interval
    }
  }

  private emit(channel: string, data: unknown) {
    const wins = BrowserWindow.getAllWindows()
    for (const win of wins) {
      win.webContents.send(channel, data)
    }
  }
}

export const feedStreamer = new FeedStreamer()
