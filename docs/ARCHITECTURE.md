# Arquitectura

```
cmd/secretguard/       CLI: parseo de opciones, códigos de salida, hook pre-commit
internal/rules/        tipos de secreto: patrón, palabras clave, gravedad, entropía mínima, cómo revocar
internal/detect/       motor: filtros, entropía, valores de ejemplo y puntaje de riesgo
internal/source/       de dónde sale el texto: archivos (concurrente), git log, git diff --cached
internal/baseline/     hallazgos aceptados, guardados como huellas
internal/report/       salida en texto, JSON y SARIF 2.1.0
internal/finding/      el tipo Finding, huellas y enmascarado
internal/testutil/     arma secretos falsos en tiempo de ejecución para los tests
```

## Decisiones

**Sin dependencias.** Go trae todo lo necesario: expresiones regulares RE2, JSON, concurrencia y
ejecución de procesos. Para git se llama al binario del sistema en lugar de usar una biblioteca: menos
código propio que mantener y el mismo comportamiento que ve el desarrollador.

**Tres filtros, del más barato al más caro.** La mayoría de las líneas no contienen ninguna palabra clave,
así que la expresión regular casi nunca corre. Después del patrón, la entropía y la lista de valores de
ejemplo eliminan `password = "changeme"` o `${TOKEN}`.

**Una coincidencia, una regla.** Las reglas van de la más específica a la más genérica. Si un token de
GitHub aparece en `api_key = "..."`, se informa como token de GitHub y no dos veces.

**Huella sin número de línea.** Así un hallazgo aceptado en la línea base no reaparece cuando alguien
agrega código arriba.

**Historial: el commit que lo introdujo.** `git log` va del más nuevo al más viejo; para cada huella se
conserva la última aparición, que es la más antigua. Si el secreto todavía está en el código, el hallazgo
del archivo se completa con ese commit; si no, se marca como "solo en el historial".

**Riesgo explicado.** El puntaje es una suma simple y visible, no una caja negra:

| Factor | Ajuste |
|---|---|
| Gravedad del tipo | crítica 70, alta 55, media 40, baja 20 |
| Está en el código actual | +15 |
| Solo en el historial | −10 |
| Ruta de pruebas o ejemplos | −30 |
| Archivo de configuración o credenciales | +10 |
| Secreto genérico con entropía ≥ 4,5 | +5 |
