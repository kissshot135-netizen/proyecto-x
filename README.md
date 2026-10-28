# SGAP: prototipo de escritorio

Aplicación sencilla en Python y Tkinter para probar el flujo de solicitudes,
aprobaciones y consulta del historial. **Esta versión no usa ni se conecta a una
base de datos**: las solicitudes, los usuarios nuevos y el historial viven en
memoria y se borran al cerrar el programa. Por eso, los cambios no se comparten
entre computadores ni entre ejecuciones.

## Requisitos

- Python 3.12 o posterior, con Tkinter disponible.
- No requiere instalar paquetes adicionales.

## Ejecutar

Desde esta carpeta, ejecuta:

```text
python sgap.py
```

## Cuentas de prueba

Todas usan la contraseña `demo123`:

| Rol | Correo |
|---|---|
| Solicitante | `solicitante@sgap.local` |
| Aprobador | `aprobador@sgap.local` |
| Administrador | `admin@sgap.local` |

El aprobador recibe un aviso emergente mediante sondeo cada tres segundos.
El administrador puede gestionar usuarios y procedimientos, consultar el
historial y exportarlo a CSV.

## Pruebas

```text
python -m unittest -v test_sgap.py
```

Las cuentas y contraseñas de demostración son solo para este prototipo; no deben
usarse como credenciales reales.
