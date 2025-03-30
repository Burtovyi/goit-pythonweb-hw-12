import sys
import os

# Додаємо кореневий каталог проекту до шляху імпорту,
# щоб модуль 'app' був доступним
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
