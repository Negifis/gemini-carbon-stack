---
name: visual-assets
description: "Raster asset generation and CSS-tokenized SVG vectorization via image-generator and vectorize.mjs."
---

# Visual Assets & Theme-Aware SVG Pipeline

Используйте при создании продуктовых иллюстраций, пустых состояний (`empty states`), диаграммных иконок и логотипов.

## 1. Выбор инструмента

- **Простые геометрические иконки и бейджи (`<= 10` примитивов):** пишите чистый ручной SVG с `viewBox`, семантическими `stroke`/`fill` и `aria-hidden="true"`.
- **Сложные плоские иллюстрации:**
  1. Сгенерируйте чистый растровый исходник через встроенный субагент `image-generator` (задавайте плоскую векторную стилистику без фотореалистичных градиентов, теней и мелкого шума, на однотонном светлом фоне `#ffffff`).
  2. Конвертируйте PNG в масштабируемый темизируемый SVG скриптом `vectorize.mjs`:
     ```powershell
     # Однократная установка локальных зависимостей в рабочей папке (без API-ключей):
     # npm i @neplex/vectorizer @resvg/resvg-js
     node "<PLUGIN_ROOT>/tools/vectorize.mjs" input.png output.svg --tokens --check ./svg-preview
     ```
  3. **Обязательный визуальный контроль:** откройте отрендеренные превью `svg-preview/*-light.png` и `*-dark.png` через `read_file` и убедитесь мультимодально, что контуры не потеряли мелкие детали и корректно читаются в обеих темах.
