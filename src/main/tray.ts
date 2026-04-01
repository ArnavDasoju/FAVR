import { Tray, Menu, nativeImage, BrowserWindow } from 'electron'

let tray: Tray | null = null

export function setupTray(mainWindow: BrowserWindow): void {
  // Create a simple 16x16 tray icon (white circle on transparent)
  const icon = nativeImage.createFromBuffer(
    Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAMklEQVQ4T2N89+7dfwYKACMDAwMDCxkGvH//ngEbIEsDTgOIdfn/MQygig2kBiO5BhAAAPJDGBFVDfWqAAAAAElFTkSuQmCC',
      'base64'
    )
  )

  tray = new Tray(icon.resize({ width: 16, height: 16 }))

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show BLD',
      click: () => {
        mainWindow.show()
        mainWindow.focus()
      }
    },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => {
        mainWindow.destroy()
        tray?.destroy()
        process.exit(0)
      }
    }
  ])

  tray.setToolTip('BLD')
  tray.setContextMenu(contextMenu)

  tray.on('click', () => {
    mainWindow.show()
    mainWindow.focus()
  })
}
