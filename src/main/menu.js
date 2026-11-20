'use strict';
// Native macOS application menu. Commands go to the renderer via `onCommand`
// ('open' | 'paste' | 'clear' | 'copy-primary'); Edit uses roles so Cmd+V is a real,
// user-initiated paste (renderer receives a `paste` event).

const { app, Menu, dialog } = require('electron');
const settings = require('./settings');

function build({ send, getWindow }) {
  const cmd = (name) => () => send(name);
  const s = settings.get();
  const dev = !app.isPackaged;
  const template = [
    {
      label: app.name,
      submenu: [
        { role: 'about' },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'File',
      submenu: [
        { label: 'Open…', accelerator: 'CmdOrCtrl+O', click: cmd('open') },
        { label: 'Scan Clipboard', accelerator: 'Shift+CmdOrCtrl+V', click: cmd('paste') },
        { type: 'separator' },
        { label: 'Clear', accelerator: 'CmdOrCtrl+K', click: cmd('clear') },
        { label: 'Clear ', accelerator: 'CmdOrCtrl+Backspace', click: cmd('clear'), visible: false, acceleratorWorksWhenHidden: true },
        { type: 'separator' },
        { role: 'close' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' }, { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' }, { role: 'copy' }, { role: 'paste' },
        { label: 'Copy Primary Result', accelerator: 'Shift+CmdOrCtrl+C', click: cmd('copy-primary') },
        { type: 'separator' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'View',
      submenu: [
        {
          id: 'auto-scan', label: 'Scan Clipboard When Activated', type: 'checkbox', checked: s.autoScanClipboard,
          click: (item) => { settings.set('autoScanClipboard', item.checked); },
        },
        { type: 'separator' },
        { role: 'togglefullscreen' },
        ...(dev ? [{ type: 'separator' }, { role: 'reload' }, { role: 'toggleDevTools' }] : []),
      ],
    },
    { role: 'windowMenu' },
    {
      role: 'help',
      submenu: [
        {
          label: 'About Privacy & Security',
          click: () => {
            const win = getWindow();
            const opts = {
              type: 'info', buttons: ['OK'], message: 'Privacy & security',
              detail: 'Everything stays on this Mac. The app never connects to the network, keeps no history, '
                + 'and writes nothing you scan to disk unless you use Save. Images are decoded by a small helper '
                + 'that runs in a strict macOS sandbox. Links only open after you confirm them.',
            };
            if (win) dialog.showMessageBox(win, opts); else dialog.showMessageBox(opts);
          },
        },
      ],
    },
  ];
  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
  return menu;
}

/** Keeps the View ▸ auto-scan checkbox in sync with the setting. */
function syncAutoScan(value) {
  const item = Menu.getApplicationMenu()?.getMenuItemById('auto-scan');
  if (item) item.checked = value;
}

module.exports = { build, syncAutoScan };
