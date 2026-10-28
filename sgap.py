"""Prototipo de escritorio del Sistema de Gestión y Autorización de Permisos."""

from __future__ import annotations

import csv
import hashlib
import hmac
import os
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk


ROLES = ("Solicitante", "Aprobador", "Administrador")
PROCEDURES = (
    "Compra de materiales",
    "Viáticos",
    "Permisos",
    "Acceso a áreas restringidas",
)
PROCEDURE_FIELDS = {
    "Compra de materiales": ("Materiales requeridos", "Monto estimado"),
    "Viáticos": ("Destino", "Fechas del viaje", "Monto estimado"),
    "Permisos": ("Motivo", "Fecha(s) solicitada(s)"),
    "Acceso a áreas restringidas": ("Área", "Motivo", "Fecha y hora"),
}
POLL_INTERVAL_MS = 3000
PASSWORD_ITERATIONS = 200_000


@dataclass
class User:
    email: str
    name: str
    role: str
    salt: bytes
    password_hash: bytes
    active: bool = True


class SGAPService:
    """Lógica de negocio temporal; los datos se pierden al cerrar el programa."""

    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.requests: list[dict[str, str]] = []
        self.history: list[dict[str, str]] = []
        self.procedures: dict[str, bool] = {name: True for name in PROCEDURES}
        self.procedure_fields = dict(PROCEDURE_FIELDS)
        self._next_request_id = 1
        self._add_demo_user("solicitante@sgap.local", "Solicitante Demo", "Solicitante")
        self._add_demo_user("aprobador@sgap.local", "Aprobador Demo", "Aprobador")
        self._add_demo_user("admin@sgap.local", "Administrador Demo", "Administrador")

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
        )

    def _add_demo_user(self, email: str, name: str, role: str) -> None:
        salt = os.urandom(16)
        self.users[email.lower()] = User(
            email=email.lower(),
            name=name,
            role=role,
            salt=salt,
            password_hash=self._hash_password("demo123", salt),
        )

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.users.get(email.strip().lower())
        if user is None or not user.active:
            return None
        candidate = self._hash_password(password, user.salt)
        return user if hmac.compare_digest(candidate, user.password_hash) else None

    def add_user(self, email: str, name: str, role: str, password: str) -> None:
        normalized_email = email.strip().lower()
        if not normalized_email or "@" not in normalized_email:
            raise ValueError("Ingresa un correo válido.")
        if normalized_email in self.users:
            raise ValueError("Ya existe un usuario con ese correo.")
        if not name.strip():
            raise ValueError("Ingresa el nombre del usuario.")
        if role not in ROLES:
            raise ValueError("Selecciona un rol válido.")
        if len(password) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres.")
        salt = os.urandom(16)
        self.users[normalized_email] = User(
            email=normalized_email,
            name=name.strip(),
            role=role,
            salt=salt,
            password_hash=self._hash_password(password, salt),
        )
        self._audit("Usuario creado", normalized_email, f"Rol: {role}")

    def set_user_active(self, email: str, active: bool) -> None:
        user = self.users[email]
        user.active = active
        action = "Usuario habilitado" if active else "Usuario deshabilitado"
        self._audit(action, email, f"Rol: {user.role}")

    def create_request(
        self, requester: User, procedure: str, details: str
    ) -> dict[str, str]:
        if requester.role != "Solicitante":
            raise ValueError("Solo un solicitante puede crear solicitudes.")
        if procedure not in self.procedures or not self.procedures[procedure]:
            raise ValueError("El procedimiento no está disponible.")
        if not details.strip():
            raise ValueError("Completa los datos de la solicitud.")
        request = {
            "id": f"SG-{self._next_request_id:04d}",
            "solicitante": requester.name,
            "correo": requester.email,
            "procedimiento": procedure,
            "detalle": details.strip(),
            "estado": "Pendiente",
            "creada": self._now(),
            "actualizada": self._now(),
            "resuelta_por": "",
        }
        self._next_request_id += 1
        self.requests.append(request)
        self._audit("Solicitud creada", request["id"], procedure)
        return request

    def resolve_request(self, request_id: str, approver: User, approved: bool) -> None:
        if approver.role != "Aprobador":
            raise ValueError("Solo un aprobador puede resolver solicitudes.")
        request = self._find_pending(request_id)
        request["estado"] = "Aprobada" if approved else "Rechazada"
        request["actualizada"] = self._now()
        request["resuelta_por"] = approver.name
        action = "Solicitud aprobada" if approved else "Solicitud rechazada"
        self._audit(action, request_id, f"Decisión de {approver.name}")

    def cancel_request(self, request_id: str, requester: User) -> None:
        request = self._find_pending(request_id)
        if request["correo"] != requester.email:
            raise ValueError("Solo puedes cancelar tus propias solicitudes.")
        request["estado"] = "Cancelada"
        request["actualizada"] = self._now()
        self._audit("Solicitud cancelada", request_id, f"Por {requester.name}")

    def toggle_procedure(self, procedure: str) -> None:
        if procedure not in self.procedures:
            raise ValueError("El procedimiento no existe.")
        self.procedures[procedure] = not self.procedures[procedure]
        state = "habilitado" if self.procedures[procedure] else "deshabilitado"
        self._audit("Procedimiento actualizado", procedure, state)

    def add_procedure(self, procedure: str, fields: tuple[str, ...]) -> None:
        name = procedure.strip()
        if not name:
            raise ValueError("Ingresa el nombre del procedimiento.")
        if name in self.procedures:
            raise ValueError("Ese procedimiento ya existe.")
        if not fields or any(not item.strip() for item in fields):
            raise ValueError("Ingresa al menos un campo y completa todos los nombres.")
        self.procedures[name] = True
        self.procedure_fields[name] = tuple(item.strip() for item in fields)
        self._audit("Procedimiento creado", name, "Habilitado")

    def _find_pending(self, request_id: str) -> dict[str, str]:
        for request in self.requests:
            if request["id"] == request_id:
                if request["estado"] != "Pendiente":
                    raise ValueError("La solicitud ya fue resuelta.")
                return request
        raise ValueError("No se encontró la solicitud.")

    def _audit(self, action: str, reference: str, details: str) -> None:
        self.history.append(
            {
                "fecha": self._now(),
                "accion": action,
                "referencia": reference,
                "detalle": details,
            }
        )

    @staticmethod
    def _now() -> str:
        return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


class SGAPApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.service = SGAPService()
        self.current_user: User | None = None
        self._poll_job: str | None = None
        self._seen_requests: set[str] = set()
        self._seen_results: set[str] = set()
        self.root.title("SGAP | Gestión de permisos")
        self.root.geometry("1020x680")
        self.root.minsize(820, 560)
        self.root.configure(bg="#f3f6fa")
        self.show_login()

    def show_login(self) -> None:
        self._cancel_poll()
        self.current_user = None
        self._clear_window()
        card = ttk.Frame(self.root, padding=34)
        card.place(relx=0.5, rely=0.47, anchor="center")
        ttk.Label(card, text="SGAP", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text="Sistema de Gestión y Autorización de Permisos",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(2, 22))
        ttk.Label(card, text="Correo").pack(anchor="w")
        self.email_entry = ttk.Entry(card, width=42)
        self.email_entry.pack(pady=(4, 12))
        ttk.Label(card, text="Contraseña").pack(anchor="w")
        self.password_entry = ttk.Entry(card, width=42, show="•")
        self.password_entry.pack(pady=(4, 18))
        ttk.Button(card, text="Iniciar sesión", command=self.login).pack(
            fill="x", ipady=5
        )
        ttk.Label(
            card,
            text=(
                "Cuentas de prueba (contraseña: demo123)\n"
                "solicitante@sgap.local  ·  aprobador@sgap.local\n"
                "admin@sgap.local"
            ),
            style="Hint.TLabel",
            justify="left",
        ).pack(anchor="w", pady=(18, 0))
        self.root.bind("<Return>", lambda _event: self.login())
        self.email_entry.focus_set()

    def login(self) -> None:
        user = self.service.authenticate(
            self.email_entry.get(), self.password_entry.get()
        )
        if user is None:
            messagebox.showerror("Acceso denegado", "Correo o contraseña incorrectos.")
            return
        self.current_user = user
        self._seen_requests = {
            request["id"]
            for request in self.service.requests
            if request["estado"] != "Pendiente"
        }
        self._seen_results = {
            request["id"]
            for request in self.service.requests
            if request["correo"] != user.email
        }
        self.show_dashboard()

    def show_dashboard(self) -> None:
        self._clear_window()
        user = self._user()
        header = ttk.Frame(self.root, padding=(22, 16))
        header.pack(fill="x")
        ttk.Label(header, text="SGAP", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header, text=f"{user.name}  ·  {user.role}", style="Subtitle.TLabel"
        ).pack(side="left", padx=18, pady=(7, 0))
        ttk.Button(header, text="Cerrar sesión", command=self.show_login).pack(
            side="right", pady=5
        )
        body = ttk.Frame(self.root, padding=(22, 0, 22, 18))
        body.pack(fill="both", expand=True)
        if user.role == "Solicitante":
            self._build_requester_panel(body)
        elif user.role == "Aprobador":
            self._build_approver_panel(body)
        else:
            self._build_admin_panel(body)
        self._schedule_poll()

    def _build_requester_panel(self, parent: ttk.Frame) -> None:
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", pady=(0, 10))
        ttk.Label(toolbar, text="Mis solicitudes", style="Section.TLabel").pack(
            side="left"
        )
        ttk.Button(
            toolbar, text="＋ Nueva solicitud", command=self._new_request_dialog
        ).pack(side="right")
        self.request_tree = self._make_tree(
            parent,
            (("id", "N.º", 90), ("procedimiento", "Procedimiento", 230),
             ("creada", "Fecha", 155), ("estado", "Estado", 120),
             ("resuelta_por", "Resuelta por", 170)),
        )
        self.request_tree.pack(fill="both", expand=True)
        ttk.Button(
            parent, text="Cancelar solicitud seleccionada", command=self._cancel_selected
        ).pack(anchor="e", pady=(10, 0))
        self._refresh_requester()

    def _build_approver_panel(self, parent: ttk.Frame) -> None:
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill="x", pady=(0, 10))
        self.pending_label = ttk.Label(toolbar, style="Section.TLabel")
        self.pending_label.pack(side="left")
        self.approver_tree = self._make_tree(
            parent,
            (("id", "N.º", 85), ("solicitante", "Solicitante", 165),
             ("procedimiento", "Procedimiento", 230), ("creada", "Fecha", 155),
             ("detalle", "Detalle", 260)),
        )
        self.approver_tree.pack(fill="both", expand=True)
        actions = ttk.Frame(parent)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(
            actions,
            text="Aprobar",
            style="Success.TButton",
            command=lambda: self._resolve_selected(True),
        ).pack(side="right", padx=(8, 0))
        ttk.Button(
            actions,
            text="Rechazar",
            style="Danger.TButton",
            command=lambda: self._resolve_selected(False),
        ).pack(side="right")
        self._refresh_approver()

    def _build_admin_panel(self, parent: ttk.Frame) -> None:
        tabs = ttk.Notebook(parent)
        tabs.pack(fill="both", expand=True)
        users_tab = ttk.Frame(tabs, padding=12)
        procedures_tab = ttk.Frame(tabs, padding=12)
        history_tab = ttk.Frame(tabs, padding=12)
        tabs.add(users_tab, text="Usuarios")
        tabs.add(procedures_tab, text="Procedimientos")
        tabs.add(history_tab, text="Historial y resumen")
        self._build_users_tab(users_tab)
        self._build_procedures_tab(procedures_tab)
        self._build_history_tab(history_tab)

    def _build_users_tab(self, parent: ttk.Frame) -> None:
        self.user_tree = self._make_tree(
            parent,
            (("name", "Nombre", 230), ("email", "Correo", 280),
             ("role", "Rol", 150), ("active", "Estado", 110)),
        )
        self.user_tree.pack(fill="both", expand=True)
        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Agregar usuario", command=self._add_user_dialog).pack(
            side="right"
        )
        ttk.Button(
            buttons, text="Habilitar / deshabilitar", command=self._toggle_user
        ).pack(side="right", padx=8)
        self._refresh_users()

    def _build_procedures_tab(self, parent: ttk.Frame) -> None:
        self.procedure_tree = self._make_tree(
            parent,
            (("name", "Procedimiento", 430), ("active", "Estado", 140)),
        )
        self.procedure_tree.pack(fill="both", expand=True)
        buttons = ttk.Frame(parent)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(
            buttons, text="Agregar procedimiento", command=self._add_procedure_dialog
        ).pack(side="right")
        ttk.Button(
            buttons,
            text="Habilitar / deshabilitar",
            command=self._toggle_procedure,
        ).pack(side="right", padx=8)
        self._refresh_procedures()

    def _build_history_tab(self, parent: ttk.Frame) -> None:
        filters = ttk.Frame(parent)
        filters.pack(fill="x", pady=(0, 10))
        ttk.Label(filters, text="Acción:").pack(side="left")
        self.history_filter = ttk.Combobox(
            filters,
            width=25,
            state="readonly",
            values=("Todas", "Solicitud creada", "Solicitud aprobada",
                    "Solicitud rechazada", "Solicitud cancelada"),
        )
        self.history_filter.set("Todas")
        self.history_filter.pack(side="left", padx=7)
        ttk.Button(filters, text="Filtrar", command=self._refresh_history).pack(
            side="left"
        )
        ttk.Button(filters, text="Exportar CSV", command=self._export_history).pack(
            side="right"
        )
        self.history_tree = self._make_tree(
            parent,
            (("fecha", "Fecha", 155), ("accion", "Acción", 190),
             ("referencia", "Referencia", 150), ("detalle", "Detalle", 300)),
        )
        self.history_tree.pack(fill="both", expand=True)
        self.stats_label = ttk.Label(parent, style="Hint.TLabel")
        self.stats_label.pack(anchor="w", pady=(8, 0))
        self._refresh_history()

    def _new_request_dialog(self) -> None:
        available = [
            name for name, active in self.service.procedures.items() if active
        ]
        if not available:
            messagebox.showinfo("Sin procedimientos", "No hay procedimientos habilitados.")
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Nueva solicitud")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Tipo de procedimiento").grid(
            row=0, column=0, sticky="w", pady=5
        )
        procedure_var = tk.StringVar(value=available[0])
        selector = ttk.Combobox(
            frame, textvariable=procedure_var, values=available, state="readonly", width=43
        )
        selector.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        fields_frame = ttk.Frame(frame)
        fields_frame.grid(row=2, column=0, sticky="ew")
        entries: list[tuple[str, ttk.Entry]] = []

        def draw_fields(_event: object = None) -> None:
            for child in fields_frame.winfo_children():
                child.destroy()
            entries.clear()
            for row, label in enumerate(
                self.service.procedure_fields.get(procedure_var.get(), ("Descripción",))
            ):
                ttk.Label(fields_frame, text=label).grid(
                    row=row * 2, column=0, sticky="w", pady=(5, 2)
                )
                entry = ttk.Entry(fields_frame, width=46)
                entry.grid(row=row * 2 + 1, column=0, sticky="ew", pady=(0, 3))
                entries.append((label, entry))

        selector.bind("<<ComboboxSelected>>", draw_fields)
        draw_fields()

        def submit() -> None:
            details = "\n".join(
                f"{label}: {entry.get().strip()}" for label, entry in entries
            )
            if any(not entry.get().strip() for _, entry in entries):
                messagebox.showerror("Datos incompletos", "Completa todos los campos.", parent=dialog)
                return
            try:
                request = self.service.create_request(
                    self._user(), procedure_var.get(), details
                )
            except ValueError as error:
                messagebox.showerror("No se pudo crear", str(error), parent=dialog)
                return
            self._refresh_requester()
            dialog.destroy()
            messagebox.showinfo(
                "Solicitud enviada",
                f"La solicitud {request['id']} fue enviada al aprobador.",
            )

        ttk.Button(frame, text="Enviar solicitud", command=submit).grid(
            row=3, column=0, sticky="e", pady=(12, 0)
        )
        dialog.bind("<Return>", lambda _event: submit())
        dialog.update_idletasks()
        dialog.geometry(f"+{self.root.winfo_rootx() + 180}+{self.root.winfo_rooty() + 80}")

    def _add_user_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Agregar usuario")
        dialog.transient(self.root)
        dialog.grab_set()
        frame = ttk.Frame(dialog, padding=18)
        frame.pack()
        fields: dict[str, tk.Widget] = {}
        for row, (key, label) in enumerate(
            (("name", "Nombre"), ("email", "Correo"), ("password", "Contraseña"))
        ):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=5)
            entry = ttk.Entry(frame, width=34, show="•" if key == "password" else "")
            entry.grid(row=row, column=1, pady=5)
            fields[key] = entry
        ttk.Label(frame, text="Rol").grid(row=3, column=0, sticky="w", pady=5)
        role = ttk.Combobox(frame, values=ROLES, state="readonly", width=31)
        role.set(ROLES[0])
        role.grid(row=3, column=1, pady=5)

        def save() -> None:
            try:
                self.service.add_user(
                    fields["email"].get(), fields["name"].get(), role.get(),
                    fields["password"].get(),
                )
            except ValueError as error:
                messagebox.showerror("Datos inválidos", str(error), parent=dialog)
                return
            dialog.destroy()
            self._refresh_users()

        ttk.Button(frame, text="Guardar", command=save).grid(
            row=4, column=1, sticky="e", pady=(10, 0)
        )

    def _add_procedure_dialog(self) -> None:
        name = simpledialog.askstring(
            "Nuevo procedimiento", "Nombre del procedimiento:", parent=self.root
        )
        if name is None:
            return
        field_text = simpledialog.askstring(
            "Campos del formulario",
            "Escribe los campos separados por coma:",
            parent=self.root,
        )
        if field_text is None:
            return
        try:
            self.service.add_procedure(
                name, tuple(field.strip() for field in field_text.split(","))
            )
        except ValueError as error:
            messagebox.showerror("Datos inválidos", str(error))
            return
        self._refresh_procedures()

    def _toggle_user(self) -> None:
        selection = self.user_tree.selection()
        if not selection:
            messagebox.showinfo("Selecciona un usuario", "Elige un usuario de la tabla.")
            return
        email = selection[0]
        user = self.service.users[email]
        if user.email == self._user().email:
            messagebox.showwarning("Acción no permitida", "No puedes deshabilitar tu cuenta.")
            return
        self.service.set_user_active(email, not user.active)
        self._refresh_users()

    def _toggle_procedure(self) -> None:
        selection = self.procedure_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Selecciona un procedimiento", "Elige un procedimiento de la tabla."
            )
            return
        self.service.toggle_procedure(selection[0])
        self._refresh_procedures()

    def _refresh_users(self) -> None:
        self._clear_tree(self.user_tree)
        for user in self.service.users.values():
            self.user_tree.insert(
                "", "end", iid=user.email,
                values=(user.name, user.email, user.role,
                        "Habilitado" if user.active else "Deshabilitado"),
            )

    def _refresh_procedures(self) -> None:
        self._clear_tree(self.procedure_tree)
        for name, active in self.service.procedures.items():
            self.procedure_tree.insert(
                "", "end", iid=name,
                values=(name, "Habilitado" if active else "Deshabilitado"),
            )

    def _refresh_requester(self) -> None:
        self._clear_tree(self.request_tree)
        for request in self.service.requests:
            if request["correo"] == self._user().email:
                self.request_tree.insert(
                    "", "end", iid=request["id"],
                    values=(request["id"], request["procedimiento"], request["creada"],
                            request["estado"], request["resuelta_por"] or "—"),
                )

    def _refresh_approver(self) -> None:
        self._clear_tree(self.approver_tree)
        pending = [r for r in self.service.requests if r["estado"] == "Pendiente"]
        self.pending_label.configure(text=f"Pendientes: {len(pending)}")
        for request in pending:
            self.approver_tree.insert(
                "", "end", iid=request["id"],
                values=(request["id"], request["solicitante"], request["procedimiento"],
                        request["creada"], request["detalle"].replace("\n", " · ")),
            )

    def _refresh_history(self) -> None:
        self._clear_tree(self.history_tree)
        selected_action = self.history_filter.get()
        rows = [
            item for item in self.service.history
            if selected_action == "Todas" or item["accion"] == selected_action
        ]
        for index, item in enumerate(reversed(rows)):
            self.history_tree.insert(
                "", "end", iid=str(index),
                values=(item["fecha"], item["accion"], item["referencia"], item["detalle"]),
            )
        requests = self.service.requests
        counts = {
            status: sum(request["estado"] == status for request in requests)
            for status in ("Pendiente", "Aprobada", "Rechazada", "Cancelada")
        }
        self.stats_label.configure(
            text=(
                f"Solicitudes: {len(requests)}   ·   Pendientes: {counts['Pendiente']}   "
                f"·   Aprobadas: {counts['Aprobada']}   ·   Rechazadas: {counts['Rechazada']}   "
                f"·   Canceladas: {counts['Cancelada']}"
            )
        )

    def _export_history(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Exportar historial",
            defaultextension=".csv",
            filetypes=(("Archivo CSV", "*.csv"),),
            initialfile="historial_sgap.csv",
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as file:
                writer = csv.DictWriter(
                    file, fieldnames=("fecha", "accion", "referencia", "detalle")
                )
                writer.writeheader()
                writer.writerows(self.service.history)
        except OSError as error:
            messagebox.showerror("Error al exportar", f"No se pudo guardar el archivo:\n{error}")
            return
        messagebox.showinfo("Exportación completa", f"Historial guardado en:\n{path}")

    def _cancel_selected(self) -> None:
        selection = self.request_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Selecciona una solicitud", "Elige una solicitud de la tabla."
            )
            return
        try:
            self.service.cancel_request(selection[0], self._user())
        except ValueError as error:
            messagebox.showerror("No se pudo cancelar", str(error))
            return
        self._refresh_requester()

    def _resolve_selected(self, approved: bool) -> None:
        selection = self.approver_tree.selection()
        if not selection:
            messagebox.showinfo(
                "Selecciona una solicitud", "Elige una solicitud pendiente de la tabla."
            )
            return
        self._resolve(selection[0], approved)

    def _resolve(self, request_id: str, approved: bool) -> None:
        try:
            self.service.resolve_request(request_id, self._user(), approved)
        except ValueError as error:
            messagebox.showerror("No se pudo resolver", str(error))
            return
        self._refresh_approver()

    def _schedule_poll(self) -> None:
        if self.current_user is not None:
            self._poll_job = self.root.after(POLL_INTERVAL_MS, self._poll)

    def _poll(self) -> None:
        self._poll_job = None
        user = self.current_user
        if user is None:
            return
        if user.role == "Aprobador":
            for request in self.service.requests:
                if request["estado"] == "Pendiente" and request["id"] not in self._seen_requests:
                    self._seen_requests.add(request["id"])
                    self._show_request_popup(request)
            self._refresh_approver()
        elif user.role == "Solicitante":
            for request in self.service.requests:
                if (
                    request["correo"] == user.email
                    and request["estado"] in ("Aprobada", "Rechazada")
                    and request["id"] not in self._seen_results
                ):
                    self._seen_results.add(request["id"])
                    messagebox.showinfo(
                        "Resultado de solicitud",
                        f"La solicitud {request['id']} fue {request['estado'].lower()}.",
                    )
            self._refresh_requester()
        else:
            self._refresh_history()
        self._schedule_poll()

    def _show_request_popup(self, request: dict[str, str]) -> None:
        popup = tk.Toplevel(self.root)
        popup.title("Nueva solicitud")
        popup.transient(self.root)
        popup.attributes("-topmost", True)
        popup.resizable(False, False)
        frame = ttk.Frame(popup, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Nueva solicitud pendiente", style="Section.TLabel").pack(
            anchor="w"
        )
        ttk.Label(
            frame,
            text=(
                f"{request['id']} · {request['procedimiento']}\n"
                f"Solicitante: {request['solicitante']}\n\n{request['detalle']}"
            ),
            justify="left",
            wraplength=360,
        ).pack(anchor="w", pady=12)
        buttons = ttk.Frame(frame)
        buttons.pack(fill="x")
        ttk.Button(
            buttons,
            text="Rechazar",
            style="Danger.TButton",
            command=lambda: self._popup_resolve(popup, request["id"], False),
        ).pack(side="right")
        ttk.Button(
            buttons,
            text="Aprobar",
            style="Success.TButton",
            command=lambda: self._popup_resolve(popup, request["id"], True),
        ).pack(side="right", padx=(0, 8))
        popup.update_idletasks()
        popup.geometry(f"+{self.root.winfo_rootx() + 120}+{self.root.winfo_rooty() + 100}")

    def _popup_resolve(self, popup: tk.Toplevel, request_id: str, approved: bool) -> None:
        self._resolve(request_id, approved)
        popup.destroy()

    def _make_tree(
        self, parent: ttk.Widget, columns: tuple[tuple[str, str, int], ...]
    ) -> ttk.Treeview:
        tree = ttk.Treeview(
            parent,
            columns=tuple(column[0] for column in columns),
            show="headings",
            selectmode="browse",
        )
        for key, title, width in columns:
            tree.heading(key, text=title)
            tree.column(key, width=width, minwidth=70, anchor="w")
        tree.tag_configure("odd", background="#f7f9fc")
        return tree

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        tree.delete(*tree.get_children())

    def _cancel_poll(self) -> None:
        if self._poll_job is not None:
            self.root.after_cancel(self._poll_job)
            self._poll_job = None

    def _clear_window(self) -> None:
        self._cancel_poll()
        for child in self.root.winfo_children():
            child.destroy()
        self.root.unbind("<Return>")

    def _user(self) -> User:
        if self.current_user is None:
            raise RuntimeError("No hay una sesión iniciada.")
        return self.current_user


def configure_styles(root: tk.Tk) -> None:
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("TFrame", background="#f3f6fa")
    style.configure("TLabel", background="#f3f6fa", foreground="#172b4d")
    style.configure("Title.TLabel", font=("Segoe UI", 25, "bold"), foreground="#123b67")
    style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#52657d")
    style.configure("Section.TLabel", font=("Segoe UI", 15, "bold"))
    style.configure("Hint.TLabel", foreground="#61758d", font=("Segoe UI", 9))
    style.configure("TButton", padding=(12, 7))
    style.configure("Success.TButton", foreground="white", background="#16794b")
    style.map("Success.TButton", background=[("active", "#12643d")])
    style.configure("Danger.TButton", foreground="white", background="#b93838")
    style.map("Danger.TButton", background=[("active", "#982d2d")])
    style.configure("Treeview", rowheight=30, font=("Segoe UI", 9))
    style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
    style.configure("TNotebook", background="#f3f6fa")
    style.configure("TNotebook.Tab", padding=(16, 8))


def main() -> None:
    root = tk.Tk()
    configure_styles(root)
    SGAPApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
