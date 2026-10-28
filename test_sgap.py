import unittest

from sgap import SGAPService


class SGAPServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = SGAPService()
        self.requester = self.service.authenticate("solicitante@sgap.local", "demo123")
        self.approver = self.service.authenticate("aprobador@sgap.local", "demo123")
        self.admin = self.service.authenticate("admin@sgap.local", "demo123")
        assert self.requester is not None
        assert self.approver is not None
        assert self.admin is not None

    def test_authentication_and_password_hashing(self) -> None:
        self.assertIsNone(self.service.authenticate("solicitante@sgap.local", "incorrecta"))
        self.assertNotEqual(
            self.service.users[self.requester.email].password_hash, b"demo123"
        )

    def test_create_and_approve_request_records_history(self) -> None:
        request = self.service.create_request(
            self.requester, "Viáticos", "Destino: Valparaíso\nFechas: 10-12"
        )
        self.service.resolve_request(request["id"], self.approver, True)
        self.assertEqual(request["estado"], "Aprobada")
        self.assertEqual(
            [entry["accion"] for entry in self.service.history],
            ["Solicitud creada", "Solicitud aprobada"],
        )

    def test_reject_request(self) -> None:
        request = self.service.create_request(
            self.requester, "Permisos", "Motivo: trámite\nFecha: 10-12"
        )
        self.service.resolve_request(request["id"], self.approver, False)
        self.assertEqual(request["estado"], "Rechazada")

    def test_requester_can_cancel_only_own_pending_request(self) -> None:
        request = self.service.create_request(
            self.requester, "Permisos", "Motivo: trámite\nFecha: 10-12"
        )
        self.service.cancel_request(request["id"], self.requester)
        self.assertEqual(request["estado"], "Cancelada")
        with self.assertRaises(ValueError):
            self.service.cancel_request(request["id"], self.requester)

    def test_only_approver_can_resolve(self) -> None:
        request = self.service.create_request(
            self.requester, "Permisos", "Motivo: trámite\nFecha: 10-12"
        )
        with self.assertRaises(ValueError):
            self.service.resolve_request(request["id"], self.admin, True)

    def test_admin_can_add_user_and_procedure(self) -> None:
        self.service.add_user("nuevo@sgap.local", "Nuevo Usuario", "Aprobador", "clave123")
        self.service.add_procedure("Reserva de sala", ("Sala", "Fecha"))
        self.assertIsNotNone(self.service.authenticate("nuevo@sgap.local", "clave123"))
        self.assertTrue(self.service.procedures["Reserva de sala"])


if __name__ == "__main__":
    unittest.main()
