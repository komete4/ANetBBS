# ANetBBS v1.1.68 — Revocación de sesiones al cambiar la contraseña, copias coherentes e interfaz en español (noviembre de 2026)

Al cambiar la contraseña, se cierran todas las demás sesiones de la cuenta en la web (incluido Socket.IO), el terminal (Telnet, SSH y rlogin), FTP y el puente MRC con autenticación compartida por cookie. Antes, una sesión iniciada con la contraseña anterior podía seguir conectada. La revocación también cierra cualquier proceso huérfano de un juego que siga asociado a una sesión revocada, sea cual sea el protocolo. Los enlaces de recuperación respetan el origen canónico de la solicitud, incluidos los dominios internacionalizados y las direcciones IPv6. La renovación de una sesión ya no puede interferir con un restablecimiento de contraseña simultáneo.

Las copias de la base de datos desde la web usan la API de copias en línea de SQLite para generar una instantánea coherente. Se verifica la copia antes de enviarla y se limita el número de reintentos si la base de datos está ocupada.

El español está disponible en la navegación, la autenticación, los tablones, los mensajes privados, el perfil, los menús integrados del terminal y el editor de traducciones. Se puede elegir desde el selector de idioma o desde el perfil. El chat IRC web incorpora traducciones al español y una interfaz adaptada a móviles.

Se corrigió un problema de sincronización en las pruebas automatizadas del puente MRC. La prueba espera el último paquete de la secuencia de entrada antes de contar los paquetes enviados.
