# secretguard

**Encuentra secretos en tu código y en tu historial de git, ordenados por riesgo real y con los pasos para revocarlos.**

[![CI](https://github.com/ulisespignatelli/secretguard/actions/workflows/ci.yml/badge.svg)](https://github.com/ulisespignatelli/secretguard/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.24-00ADD8)
![Dependencias](https://img.shields.io/badge/dependencias-0-brightgreen)
![Licencia](https://img.shields.io/badge/licencia-MIT-blue)

![secretguard en acción](docs/demo.png)

Claves de AWS, tokens de GitHub, credenciales de Mercado Pago o Stripe, URLs de bases de datos con contraseña,
claves privadas: un secreto subido a un repositorio es una de las formas más comunes de comprometer una
organización. Y borrarlo del archivo no alcanza, porque queda en el historial de git.

secretguard los encuentra antes que otros, y responde las tres preguntas que importan:

1. **¿Qué tan grave es?** Cada hallazgo tiene un puntaje de 0 a 100 que combina el tipo de secreto con su
   contexto: ¿está en el código actual o solo en el historial? ¿En un `.env` o en una carpeta de tests?
2. **¿Por qué?** El puntaje viene explicado, para que decidas rápido.
3. **¿Qué hago?** Cada tipo de secreto trae los pasos para revocarlo en su proveedor.

## Qué lo diferencia

| | |
|---|---|
| **Cero dependencias** | Solo la biblioteca estándar de Go. Una herramienta de seguridad no debería sumar cadena de suministro que atacar. |
| **Riesgo, no solo coincidencias** | Ordena por puntaje: lo crítico y vigente primero, el JWT de prueba al final. |
| **Nunca muestra el secreto** | Ni en la terminal ni en los informes: solo los primeros caracteres y una huella. |
| **Historial completo** | Revisa todas las ramas y te dice en qué commit entró cada secreto, o si ya solo vive en el historial. |
| **Directo desde GitHub** | Un repo, todos los de un usuario o los de una organización, con enlace a cada línea. |
| **Proveedores de la región** | Mercado Pago, además de AWS, GitHub, GitLab, Stripe, Google, Slack, OpenAI, Anthropic y más. |
| **Listo para CI** | SARIF para la pestaña *Security* de GitHub, GitHub Action, hook pre-commit y línea base. |

## Plataformas

secretguard está pensado y probado principalmente en **Linux** (Kali, Ubuntu, Debian), que es donde se usa
el día a día en seguridad y en servidores de CI. También funciona en **macOS** y **Windows**: el CI corre los
tests en los tres sistemas en cada cambio.

| Sistema | Estado | Notas |
|---|---|---|
| **Linux** (Kali, Ubuntu, Debian…) | ✅ Recomendado | Probado en Kali Linux |
| **macOS** | ✅ Soportado | Intel y Apple Silicon |
| **Windows 10/11** | ✅ Soportado | El *Control inteligente de aplicaciones* de Windows 11 puede bloquear ejecutables sin firma (ver abajo) |

Requisitos: **git** instalado (para `--history`, `--staged`, el hook y el escaneo de GitHub). Para compilar,
**Go 1.24.7 o superior**.

## Instalación

### Linux (Kali, Ubuntu, Debian)

**Opción 1: compilar con Go**

```bash
sudo apt update && sudo apt install -y golang-go git
go install github.com/ulisespignatelli/secretguard/cmd/secretguard@latest
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc && source ~/.zshrc   # en Kali; con bash usá ~/.bashrc
secretguard version
```

**Opción 2: ejecutable ya compilado** (desde [Releases](https://github.com/ulisespignatelli/secretguard/releases))

```bash
VERSION=v0.2.0
curl -LO https://github.com/ulisespignatelli/secretguard/releases/download/$VERSION/secretguard_linux_amd64
curl -LO https://github.com/ulisespignatelli/secretguard/releases/download/$VERSION/checksums.txt
sha256sum --check --ignore-missing checksums.txt      # tiene que decir OK
sudo install -m 755 secretguard_linux_amd64 /usr/local/bin/secretguard
```

En equipos ARM (Raspberry Pi, por ejemplo) usá `secretguard_linux_arm64`.

**Opción 3: desde el código**

```bash
git clone https://github.com/ulisespignatelli/secretguard.git
cd secretguard
go build -o secretguard ./cmd/secretguard
sudo install -m 755 secretguard /usr/local/bin/
```

### macOS

```bash
brew install go
go install github.com/ulisespignatelli/secretguard/cmd/secretguard@latest
```

O el ejecutable `secretguard_darwin_arm64` (Apple Silicon) / `secretguard_darwin_amd64` (Intel) de Releases.

### Windows

Instalá Go desde [go.dev/dl](https://go.dev/dl) y, en PowerShell:

```powershell
go install github.com/ulisespignatelli/secretguard/cmd/secretguard@latest
secretguard version
```

O descargá `secretguard_windows_amd64.exe` de Releases.

> **Control inteligente de aplicaciones (Windows 11):** si Windows responde *"Una directiva de Control de
> aplicaciones bloqueó este archivo"*, es porque el ejecutable no tiene firma digital. No hace falta
> desactivar esa protección: podés usar secretguard dentro de **WSL** (`wsl --install -d Ubuntu` y seguir
> los pasos de Linux).

## Uso

### Comandos

| Comando | Qué hace |
|---|---|
| `secretguard scan [ruta]` | Escanea una carpeta o un archivo (por defecto, la carpeta actual) |
| `secretguard scan [ruta] --history` | Además, todo el historial de git (todas las ramas) |
| `secretguard scan --staged` | Solo los cambios preparados para commit |
| `secretguard github duenio/repo` | Escanea un repo de GitHub sin clonarlo a mano |
| `secretguard github --user NOMBRE` | Todos los repos de un usuario |
| `secretguard github --org NOMBRE` | Todos los repos de una organización |
| `secretguard baseline [ruta]` | Acepta los hallazgos actuales (archivo de línea base) |
| `secretguard hook install` | Instala el hook pre-commit en el repo actual |
| `secretguard rules` | Lista los 21 tipos de secreto que detecta |
| `secretguard version` | Muestra la versión |
| `secretguard help` | Muestra la ayuda |

### Directo desde GitHub

No hace falta clonar nada: secretguard trae el repositorio con todo su historial a una carpeta temporal,
lo revisa y la borra.

```bash
secretguard github ulisespignatelli/argos
secretguard github https://github.com/ulisespignatelli/argos
secretguard scan https://github.com/ulisespignatelli/argos     # equivalente
secretguard github --user ulisespignatelli --no-history       # todos tus repos, solo código actual
secretguard github --org mi-empresa --forks --max-repos 100
```

| Opción | Para qué |
|---|---|
| `--no-history` | solo el código actual (más rápido) |
| `--forks` | incluye forks (por defecto se omiten) |
| `--archived=false` | omite los repos archivados |
| `--max-repos N` | tope de repositorios, los de actividad más reciente primero (por defecto 50) |

Cada hallazgo trae el enlace directo a la línea en GitHub (o al commit, si ya solo vive en el historial),
y suma riesgo si el repositorio es público.

**Repos privados:** definí `GITHUB_TOKEN` (o `GH_TOKEN`) con permiso de solo lectura. El token se lee del
entorno, nunca de un argumento (que quedaría en el historial del shell), y no se guarda:

```bash
read -s GITHUB_TOKEN && export GITHUB_TOKEN      # Linux/macOS: lo escribís sin que se vea
secretguard github mi-usuario/repo-privado
unset GITHUB_TOKEN
```

```powershell
$env:GITHUB_TOKEN = Read-Host -MaskInput "Token"  # Windows (PowerShell 7)
```

Sin token, la API de GitHub permite unas 60 consultas por hora: alcanza para `--user` en cuentas normales.

### En tu máquina

```bash
secretguard scan                                  # la carpeta actual
secretguard scan ./mi-proyecto --history          # también todo el historial de git
secretguard scan config.env                       # un archivo suelto
secretguard scan --format json --output informe.json
secretguard scan --format sarif --output resultados.sarif
secretguard scan --fail-on alta --min-score 60
secretguard scan --exclude "docs/**,*.min.js,testdata/**"
```

| Opción | Para qué |
|---|---|
| `--history` | revisa las líneas agregadas en todos los commits de todas las ramas |
| `--staged` | solo lo preparado para commit (lo usa el hook) |
| `--format` | `text` (por defecto), `json` o `sarif` |
| `--output` | escribe el informe en un archivo (con permisos 600) |
| `--fail-on` | gravedad desde la que sale con código 1: `baja` (por defecto), `media`, `alta`, `critica` |
| `--min-score` | oculta lo que tenga menos riesgo que N (0-100) |
| `--baseline` | archivo de hallazgos aceptados (por defecto `.secretguard-baseline.json` si existe) |
| `--exclude` | patrones glob separados por coma |
| `--workers` | archivos en paralelo (por defecto 8) |

Las opciones van antes o después de la ruta, como prefieras. Códigos de salida: `0` sin hallazgos,
`1` con hallazgos, `2` error. Para salida sin colores: `NO_COLOR=1`.

### Antes de cada commit

```bash
cd mi-repo
secretguard hook install
```

Desde ahí, un commit con un secreto se frena antes de existir (`git commit --no-verify` lo saltea, pero no
es recomendable). Requiere que `secretguard` esté en el PATH. También funciona con
[pre-commit](https://pre-commit.com):

```yaml
repos:
  - repo: https://github.com/ulisespignatelli/secretguard
    rev: v0.2.0
    hooks:
      - id: secretguard
```

### En GitHub Actions

```yaml
jobs:
  secretos:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # historial completo
      - uses: ulisespignatelli/secretguard@v0.2.0
        with:
          fail-on: media
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secretguard.sarif
```

Los hallazgos aparecen en la pestaña **Security → Code scanning** del repositorio.

### Falsos positivos

- En la línea: agregá el comentario `secretguard:allow` (con un motivo, idealmente).
- Para aceptar lo que ya existe y frenar solo lo nuevo: `secretguard baseline` crea
  `.secretguard-baseline.json`, que guarda **huellas**, nunca secretos. Los siguientes `scan` lo usan solos.
- Para excluir carpetas enteras: `--exclude "fixtures/**"`.

Aceptar un hallazgo no lo vuelve seguro: si el secreto era real, igual hay que rotarlo.

## Cómo funciona

```
archivos ──┐                        ┌─ texto (terminal)
           ├─► detector ─► riesgo ─►├─ JSON
git log ───┘   (reglas,    (tipo +  └─ SARIF 2.1.0
git diff       entropía,   contexto)
               ejemplos)
```

1. **Recorrido concurrente:** varias goroutines leen archivos en paralelo. Se saltean binarios, archivos
   grandes y carpetas de dependencias (`node_modules`, `vendor`, `.venv`…).
2. **Detección en tres filtros:** palabras clave baratas primero, expresión regular después, y al final
   entropía de Shannon más una lista de valores de ejemplo (`changeme`, `${VAR}`, `os.environ`…) para
   descartar falsos positivos.
3. **Historial:** `git log -p --all` sin shell y sin extensiones de diff externas; solo se analizan las
   líneas agregadas, con el commit y la fecha en que entró cada secreto.
4. **Riesgo:** gravedad del tipo, más o menos según contexto (código actual, solo historial, ruta de
   pruebas, archivo de configuración, entropía).

Más detalle en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Desarrollo

```bash
go test -race ./...
go vet ./...
go run ./cmd/secretguard scan . --history
```

Los tests arman los secretos falsos en tiempo de ejecución (concatenando partes), así el propio repositorio
no contiene nada con forma de secreto. El CI corre en Windows, Linux y macOS, ejecuta `govulncheck` y
secretguard se escanea a sí mismo en cada cambio.

## Hoja de ruta

- `--verify`: confirmar si un secreto sigue activo, con una consulta de solo lectura al proveedor y
  solo con autorización explícita
- Reglas propias en un archivo de configuración
- Escaneo de imágenes de contenedores
- Escaneo de issues, pull requests y gists de GitHub

## Uso responsable

secretguard está pensado para revisar **tus** repositorios o aquellos en los que tenés autorización. Si
encontrás un secreto en un proyecto ajeno, avisale a sus responsables de forma privada. Ver
[SECURITY.md](SECURITY.md).

## Licencia

MIT.
