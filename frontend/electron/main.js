import { app, BrowserWindow } from "electron";
import * as path from "path";

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 800,
    webPreferences: {
      contextIsolation: true,
    },
  });

  const isDev = !app.isPackaged;
  const URL = isDev
    ? "http://localhost:3000"
    : `file://${path.resolve(__dirname, "../out/index.html")}`;

  win.loadURL(URL);
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
