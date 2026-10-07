import sys
import json
import sqlite3
import secrets
import hmac
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QInputDialog,
    QSplitter,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

APP_NAME = "Secure Diary"
DB_PATH = Path(__file__).with_name("secure_diary.db")
KDF_N = 2**14
KDF_R = 8
KDF_P = 1
KEY_LENGTH = 32
NONCE_LENGTH = 12
VERIFIER_TEXT = b"SECURE_DIARY_PASSWORD_CHECK_v1"


def utc_now_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def display_time(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    kdf = Scrypt(
        salt=salt,
        length=KEY_LENGTH,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(NONCE_LENGTH)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


class DiaryDatabase:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA secure_delete = ON")
        self._create_schema()

    def _create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_utc TEXT NOT NULL,
                updated_utc TEXT NOT NULL,
                nonce BLOB NOT NULL,
                ciphertext BLOB NOT NULL
            );
            """
        )
        self.conn.commit()

    def has_password(self) -> bool:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='password_check'"
        ).fetchone()
        return row is not None

    def get_salt(self) -> bytes:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='salt'"
        ).fetchone()
        if row is None:
            raise RuntimeError("Diary encryption salt is missing.")
        return bytes(row[0])

    def initialize_password(self, password: str) -> bytes:
        if self.has_password():
            raise RuntimeError("The diary password is already initialized.")
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        nonce, ciphertext = encrypt_bytes(key, VERIFIER_TEXT)
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?)",
            ("salt", salt),
        )
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?)",
            ("password_check", nonce + ciphertext),
        )
        self.conn.commit()
        return key

    def verify_password(self, password: str) -> bytes | None:
        if not self.has_password():
            return None
        salt = self.get_salt()
        key = derive_key(password, salt)
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key='password_check'"
        ).fetchone()
        packed = bytes(row[0])
        nonce, ciphertext = packed[:NONCE_LENGTH], packed[NONCE_LENGTH:]
        try:
            check = decrypt_bytes(key, nonce, ciphertext)
        except Exception:
            return None
        if not hmac.compare_digest(check, VERIFIER_TEXT):
            return None
        return key

    def list_entries(self):
        return self.conn.execute(
            "SELECT id, created_utc, updated_utc FROM entries ORDER BY updated_utc DESC"
        ).fetchall()

    def insert_entry(self, key: bytes, payload: dict) -> int:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        nonce, ciphertext = encrypt_bytes(key, raw)
        now = utc_now_text()
        cur = self.conn.execute(
            """
            INSERT INTO entries(created_utc, updated_utc, nonce, ciphertext)
            VALUES (?, ?, ?, ?)
            """,
            (now, now, nonce, ciphertext),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_entry(self, key: bytes, entry_id: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        nonce, ciphertext = encrypt_bytes(key, raw)
        self.conn.execute(
            """
            UPDATE entries
            SET updated_utc = ?, nonce = ?, ciphertext = ?
            WHERE id = ?
            """,
            (utc_now_text(), nonce, ciphertext, entry_id),
        )
        self.conn.commit()

    def read_entry(self, key: bytes, entry_id: int) -> dict:
        row = self.conn.execute(
            "SELECT nonce, ciphertext FROM entries WHERE id=?",
            (entry_id,),
        ).fetchone()
        if row is None:
            raise KeyError("Diary entry no longer exists.")
        raw = decrypt_bytes(key, bytes(row[0]), bytes(row[1]))
        return json.loads(raw.decode("utf-8"))

    def delete_entry(self, entry_id: int) -> None:
        self.conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


class PasswordDialog(QDialog):
    def __init__(self, setup_mode: bool, parent=None):
        super().__init__(parent)
        self.setup_mode = setup_mode
        self.setWindowTitle("Create Diary Password" if setup_mode else "Unlock Diary")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Create a strong password for your diary.\n"
            "The password is not stored; it is used to derive the encryption key."
            if setup_mode
            else "Enter your diary password to decrypt your entries."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Password:", self.password)

        self.confirm = None
        if setup_mode:
            self.confirm = QLineEdit()
            self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Confirm:", self.confirm)

        layout.addLayout(form)

        self.error = QLabel()
        self.error.setStyleSheet("color: #b42318;")
        self.error.setWordWrap(True)
        layout.addWidget(self.error)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.validate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.password.returnPressed.connect(self.validate)
        if self.confirm:
            self.confirm.returnPressed.connect(self.validate)

    def validate(self) -> None:
        password = self.password.text()
        if not password:
            self.error.setText("Password cannot be empty.")
            return
        if self.setup_mode:
            if len(password) < 10:
                self.error.setText("Use at least 10 characters for the diary password.")
                return
            if password != self.confirm.text():
                self.error.setText("The two passwords do not match.")
                return
        self.accept()

    def value(self) -> str:
        return self.password.text()


class EntryEditor(QDialog):
    def __init__(self, title="New Entry", existing=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 620)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.title_edit = QLineEdit()
        self.title_edit.setPlaceholderText("Diary entry title")
        form.addRow("Title:", self.title_edit)
        layout.addLayout(form)

        self.body = QTextEdit()
        self.body.setPlaceholderText("Write your diary entry here...")
        self.body.setAcceptRichText(False)
        layout.addWidget(self.body, 1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if existing:
            self.title_edit.setText(existing.get("title", ""))
            self.body.setPlainText(existing.get("body", ""))
            self._source_name = existing.get("source_name")
        else:
            self._source_name = None

    def get_payload(self) -> dict:
        return {
            "title": self.title_edit.text().strip() or "Untitled Entry",
            "body": self.body.toPlainText(),
            "source_name": self._source_name,
        }


class SecureDiary(QMainWindow):
    def __init__(self, db: DiaryDatabase, key: bytes):
        super().__init__()
        self.db = db
        self.key = key
        self.current_entry_id: int | None = None
        self.entry_cache: dict[int, dict] = {}

        self.setWindowTitle(APP_NAME)
        self.resize(1180, 760)
        self.setMinimumSize(900, 600)

        self._build_ui()
        self._build_menu()
        self._refresh_list()

    def _build_ui(self):
        toolbar = QToolBar("Diary Toolbar")
        toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(toolbar)

        new_action = QAction("New Entry", self)
        new_action.triggered.connect(self.new_entry)
        toolbar.addAction(new_action)

        import_action = QAction("Import Text", self)
        import_action.triggered.connect(self.import_text)
        toolbar.addAction(import_action)

        toolbar.addSeparator()
        save_action = QAction("Save", self)
        save_action.triggered.connect(self.save_current)
        toolbar.addAction(save_action)

        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(self.delete_current)
        toolbar.addAction(delete_action)

        toolbar.addSeparator()
        lock_action = QAction("Lock", self)
        lock_action.triggered.connect(self.lock)
        toolbar.addAction(lock_action)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14, 14, 14, 14)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        outer.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)

        search_row = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search diary entries...")
        self.search.textChanged.connect(self._refresh_list)
        search_row.addWidget(self.search)
        left_layout.addLayout(search_row)

        self.entry_list = QListWidget()
        self.entry_list.currentItemChanged.connect(self._list_selection_changed)
        left_layout.addWidget(self.entry_list, 1)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(10, 0, 0, 0)

        self.title_label = QLabel("No entry selected")
        self.title_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self.title_label.setWordWrap(True)
        right_layout.addWidget(self.title_label)

        self.meta_label = QLabel("")
        self.meta_label.setStyleSheet("color: #667085;")
        right_layout.addWidget(self.meta_label)

        self.content = QTextEdit()
        self.content.setReadOnly(True)
        self.content.setAcceptRichText(False)
        right_layout.addWidget(self.content, 1)

        button_row = QHBoxLayout()
        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.edit_current)
        self.edit_button.setEnabled(False)
        button_row.addWidget(self.edit_button)

        self.open_source_button = QPushButton("Source Info")
        self.open_source_button.clicked.connect(self.show_source_info)
        self.open_source_button.setEnabled(False)
        button_row.addWidget(self.open_source_button)
        button_row.addStretch()
        right_layout.addLayout(button_row)

        splitter.addWidget(right)
        splitter.setSizes([300, 850])

        self.statusBar().showMessage("Diary unlocked")

    def _build_menu(self):
        menu = self.menuBar()
        file_menu = menu.addMenu("File")

        action = QAction("New Entry", self)
        action.triggered.connect(self.new_entry)
        file_menu.addAction(action)

        action = QAction("Import Text File", self)
        action.triggered.connect(self.import_text)
        file_menu.addAction(action)

        file_menu.addSeparator()
        action = QAction("Lock Diary", self)
        action.triggered.connect(self.lock)
        file_menu.addAction(action)

        file_menu.addSeparator()
        action = QAction("Exit", self)
        action.triggered.connect(self.close)
        file_menu.addAction(action)

    def _refresh_list(self):
        query = self.search.text().strip().lower() if hasattr(self, "search") else ""
        selected_id = self.current_entry_id
        self.entry_list.blockSignals(True)
        self.entry_list.clear()

        rows = self.db.list_entries()
        for row in rows:
            entry_id = int(row["id"])
            try:
                payload = self.db.read_entry(self.key, entry_id)
            except Exception:
                continue
            self.entry_cache[entry_id] = payload
            title = payload.get("title", "Untitled Entry")
            if query and query not in title.lower() and query not in payload.get("body", "").lower():
                continue

            item = QListWidgetItem(title)
            item.setData(Qt.ItemDataRole.UserRole, entry_id)
            item.setToolTip(
                f"Updated {display_time(row['updated_utc'])}"
            )
            self.entry_list.addItem(item)

        self.entry_list.blockSignals(False)

        if selected_id is not None:
            for i in range(self.entry_list.count()):
                if self.entry_list.item(i).data(Qt.ItemDataRole.UserRole) == selected_id:
                    self.entry_list.setCurrentRow(i)
                    break

    def _list_selection_changed(self, current, previous):
        del previous
        if current is None:
            self._clear_view()
            return
        entry_id = current.data(Qt.ItemDataRole.UserRole)
        self._show_entry(int(entry_id))

    def _show_entry(self, entry_id: int):
        try:
            payload = self.db.read_entry(self.key, entry_id)
        except Exception as exc:
            QMessageBox.critical(self, "Decryption Error", str(exc))
            return

        self.current_entry_id = entry_id
        self.entry_cache[entry_id] = payload
        self.title_label.setText(payload.get("title", "Untitled Entry"))
        self.content.setPlainText(payload.get("body", ""))

        row = self.db.conn.execute(
            "SELECT created_utc, updated_utc FROM entries WHERE id=?",
            (entry_id,),
        ).fetchone()
        source = payload.get("source_name")
        source_text = f"Imported from: {source}" if source else "Written in diary"
        self.meta_label.setText(
            f"Created: {display_time(row['created_utc'])}  •  "
            f"Updated: {display_time(row['updated_utc'])}  •  {source_text}"
        )
        self.edit_button.setEnabled(True)
        self.open_source_button.setEnabled(bool(source))

    def _clear_view(self):
        self.current_entry_id = None
        self.title_label.setText("No entry selected")
        self.meta_label.setText("")
        self.content.clear()
        self.edit_button.setEnabled(False)
        self.open_source_button.setEnabled(False)

    def new_entry(self):
        dialog = EntryEditor("New Diary Entry", parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        payload = dialog.get_payload()
        entry_id = self.db.insert_entry(self.key, payload)
        self.current_entry_id = entry_id
        self._refresh_list()
        self._select_entry_id(entry_id)

    def import_text(self):
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Import Text Files",
            "",
            "Text files (*.txt *.md *.csv *.log *.json);;All files (*.*)",
        )
        if not paths:
            return

        imported = 0
        failed = []
        for raw_path in paths:
            path = Path(raw_path)
            try:
                try:
                    text = path.read_text(encoding="utf-8-sig")
                except UnicodeDecodeError:
                    text = path.read_text(encoding="cp1252")
                payload = {
                    "title": path.stem,
                    "body": text,
                    "source_name": path.name,
                }
                self.db.insert_entry(self.key, payload)
                imported += 1
            except Exception as exc:
                failed.append(f"{path.name}: {exc}")

        self._refresh_list()
        if failed:
            QMessageBox.warning(
                self,
                "Import Finished With Errors",
                f"Imported {imported} file(s).\n\n" + "\n".join(failed),
            )
        else:
            self.statusBar().showMessage(f"Imported and encrypted {imported} file(s).")

    def edit_current(self):
        if self.current_entry_id is None:
            return
        try:
            existing = self.db.read_entry(self.key, self.current_entry_id)
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
            return
        dialog = EntryEditor("Edit Diary Entry", existing=existing, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.db.update_entry(self.key, self.current_entry_id, dialog.get_payload())
        selected = self.current_entry_id
        self._refresh_list()
        self._select_entry_id(selected)

    def save_current(self):
        # Entries are encrypted immediately on New/Edit. This action exists as a
        # clear user-facing command, and simply confirms the selected entry is saved.
        if self.current_entry_id is None:
            self.statusBar().showMessage("No entry selected.")
        else:
            self.statusBar().showMessage("Selected entry is already encrypted and saved.")

    def delete_current(self):
        if self.current_entry_id is None:
            return
        reply = QMessageBox.question(
            self,
            "Delete Entry",
            "Permanently delete this diary entry? This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        entry_id = self.current_entry_id
        self.db.delete_entry(entry_id)
        self.entry_cache.pop(entry_id, None)
        self._clear_view()
        self._refresh_list()
        self.statusBar().showMessage("Entry deleted.")

    def show_source_info(self):
        if self.current_entry_id is None:
            return
        payload = self.db.read_entry(self.key, self.current_entry_id)
        source = payload.get("source_name")
        if source:
            QMessageBox.information(
                self,
                "Imported Text",
                f"Original filename: {source}\n\n"
                "The diary stores the imported text as encrypted diary content. "
                "It does not modify the original file.",
            )

    def _select_entry_id(self, entry_id: int):
        for i in range(self.entry_list.count()):
            item = self.entry_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == entry_id:
                self.entry_list.setCurrentRow(i)
                return

    def lock(self):
        self.key = b""
        self.current_entry_id = None
        self.entry_cache.clear()
        self.entry_list.clear()
        self._clear_view()
        self.hide()
        self._reopen_after_lock()

    def _reopen_after_lock(self):
        password, ok = QInputDialog.getText(
            self,
            "Unlock Diary",
            "Enter your diary password:",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            QApplication.quit()
            return
        key = self.db.verify_password(password)
        if key is None:
            QMessageBox.critical(self, "Unlock Failed", "Incorrect diary password.")
            QApplication.quit()
            return
        self.key = key
        self._refresh_list()
        self.show()
        self.statusBar().showMessage("Diary unlocked")

    def closeEvent(self, event):
        self.key = b""
        self.entry_cache.clear()
        try:
            self.db.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        self.db.close()
        event.accept()


def authenticate(db: DiaryDatabase) -> bytes | None:
    app = QApplication.instance()
    if app is None:
        raise RuntimeError("QApplication must exist before authentication.")

    if not db.has_password():
        dialog = PasswordDialog(setup_mode=True)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        try:
            return db.initialize_password(dialog.value())
        except Exception as exc:
            QMessageBox.critical(None, "Setup Error", str(exc))
            return None

    for _ in range(5):
        dialog = PasswordDialog(setup_mode=False)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        key = db.verify_password(dialog.value())
        if key is not None:
            return key
        QMessageBox.warning(None, "Incorrect Password", "That password could not unlock the diary.")
    QMessageBox.critical(None, "Locked", "Too many incorrect attempts. The diary will close.")
    return None


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")

    app.setStyleSheet(
        """
        QMainWindow, QWidget { background: #f7f4ee; color: #202124; }
        QToolBar { background: #eee9df; border: 0; spacing: 6px; padding: 6px; }
        QToolButton { padding: 7px 10px; }
        QListWidget, QTextEdit, QLineEdit {
            background: #fffdf9;
            border: 1px solid #d7d1c7;
            border-radius: 6px;
        }
        QListWidget::item { padding: 10px; border-bottom: 1px solid #ebe5db; }
        QListWidget::item:selected { background: #ded8cd; color: #202124; }
        QPushButton {
            background: #e4ded3;
            border: 1px solid #cfc7bb;
            border-radius: 6px;
            padding: 8px 14px;
        }
        QPushButton:hover { background: #d9d1c5; }
        QLabel { background: transparent; }
        """
    )

    db = DiaryDatabase(DB_PATH)
    try:
        key = authenticate(db)
        if key is None:
            db.close()
            return 0
        window = SecureDiary(db, key)
        window.show()
        return app.exec()
    except Exception as exc:
        QMessageBox.critical(None, "Fatal Error", str(exc))
        db.close()
        return 1


if __name__ == "__main__":
    sys.exit(main())
