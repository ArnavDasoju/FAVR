/**
 * Screenshot Capture — takes before/after screenshots of a dev server.
 * Uses Puppeteer to capture the page state for VLM validation.
 */

let puppeteerModule: any = null

async function getPuppeteer(): Promise<any> {
  if (!puppeteerModule) {
    try {
      // @ts-ignore — puppeteer is optional, loaded at runtime
      puppeteerModule = await import('puppeteer')
    } catch {
      console.warn('[screenshot] puppeteer not available — screenshots disabled')
      return null
    }
  }
  return puppeteerModule
}

export interface ScreenshotResult {
  base64: string
  width: number
  height: number
  timestamp: number
}

/**
 * Capture a screenshot of a URL as base64.
 */
export async function captureScreenshot(
  url: string,
  options: {
    width?: number
    height?: number
    waitFor?: number
    fullPage?: boolean
  } = {}
): Promise<ScreenshotResult | null> {
  const { width = 1280, height = 800, waitFor = 2000, fullPage = false } = options

  try {
    const pup = await getPuppeteer()
    if (!pup) return null

    const browser = await pup.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage']
    })

    const page = await browser.newPage()
    await page.setViewport({ width, height })

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 })

    // Extra wait for JS rendering
    if (waitFor > 0) {
      await new Promise((r) => setTimeout(r, waitFor))
    }

    const screenshot = await page.screenshot({
      encoding: 'base64',
      fullPage,
      type: 'png'
    })

    await browser.close()

    return {
      base64: screenshot as string,
      width,
      height,
      timestamp: Date.now()
    }
  } catch (err) {
    console.error('[screenshot] capture failed:', err)
    return null
  }
}

/**
 * Check if a dev server is reachable.
 */
export async function isServerReachable(url: string, timeout = 5000): Promise<boolean> {
  try {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeout)
    const response = await fetch(url, { signal: controller.signal })
    clearTimeout(timer)
    return response.ok || response.status < 500
  } catch {
    return false
  }
}

/**
 * Capture before/after screenshots for diff comparison.
 */
export async function captureBeforeAfter(
  url: string
): Promise<{ before: ScreenshotResult | null; after: ScreenshotResult | null }> {
  // "Before" is captured before agent starts (should be called pre-execution)
  // "After" is captured after agent completes
  // For now, we just capture the current state as "after"
  const after = await captureScreenshot(url)
  return { before: null, after }
}

/**
 * Capture console errors from a page.
 */
export async function captureConsoleErrors(url: string): Promise<string[]> {
  try {
    const pup = await getPuppeteer()
    if (!pup) return []

    const browser = await pup.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    })

    const page = await browser.newPage()
    const errors: string[] = []

    page.on('console', (msg: any) => {
      if (msg.type() === 'error') {
        errors.push(msg.text())
      }
    })

    page.on('pageerror', (err: any) => {
      errors.push(err.message)
    })

    await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 })
    await new Promise((r) => setTimeout(r, 2000))

    await browser.close()
    return errors
  } catch {
    return []
  }
}
