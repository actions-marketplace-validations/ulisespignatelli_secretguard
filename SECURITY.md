# Seguridad

## Reportar una vulnerabilidad

Si encontrás una falla en secretguard, usá **Security → Report a vulnerability** en GitHub (aviso privado).
No abras un issue público. Respondo dentro de los 7 días.

## Modelo de amenazas

secretguard maneja justamente lo que se quiere proteger: secretos. El diseño parte de esa premisa.

| Riesgo | Cómo se mitiga |
|---|---|
| Que el informe filtre el secreto (logs de CI, capturas, SARIF público) | Ninguna salida contiene el secreto completo: solo los primeros caracteres y una huella SHA-256. Hay tests que lo verifican en los tres formatos. |
| Que la línea base se vuelva un listado de secretos | Guarda huellas (hash de regla + archivo + hash del secreto), nunca el valor. Se escribe con permisos 600. |
| Ataque a la cadena de suministro | Cero dependencias externas: solo la biblioteca estándar de Go. `govulncheck` en cada cambio y binarios publicados con suma SHA-256. |
| Repositorio malicioso que ejecuta código al escanearlo | git se invoca sin shell, con argumentos fijos, `--no-ext-diff` y `--no-textconv` para no ejecutar filtros definidos por el repo. No se ejecutan hooks. |
| Clonar un repositorio de GitHub malicioso | Se clona en una carpeta temporal que se borra al terminar, con `core.hooksPath` apuntando a una carpeta vacía, sin submódulos, sin enlaces simbólicos y con `protocol.file.allow=never`. El nombre del repo se valida antes de armar la URL. |
| Filtrar el token de GitHub | Se lee solo de `GITHUB_TOKEN`/`GH_TOKEN` (nunca de un argumento, que quedaría en el historial del shell), viaja como cabecera HTTP de git y se enmascara en cualquier mensaje de error. |
| Expresiones regulares lentas (ReDoS) | El motor de Go (RE2) garantiza tiempo lineal. Además se saltean líneas de más de 4096 caracteres y archivos de más de 2 MB. |
| Falsos negativos | Un secreto con un formato no contemplado puede pasar. secretguard es una capa más, no reemplaza la rotación periódica ni un gestor de secretos. |
| Uso contra terceros | La herramienta no se conecta a ningún proveedor ni prueba los secretos. La verificación futura (`--verify`) será opcional y explícita. |
