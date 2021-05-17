# DDoS
Для установки приложения DDoS на контроллер RUNOS 2.0 необходимо:
1. Перейти в директорию с приложениями для контроллера: cd /runos/src/apps
2. Загрузить репозиторий с исходными данными приложения DDoS, HostManager, L2LearningSwitch.
3. апустить nix-shell в директории runos
4. Пересобрать контроллер. Для этого надо перейти в директорию build.

mkdir build

cd build

cmake ..

make

5. Запустить контроллер

cd ..

./build/runos
