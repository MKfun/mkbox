# mkbox
<a href="">[![siski](https://img.shields.io/badge/%D0%9F%D0%BE%D0%B7%D0%B4%D0%BD%D1%8F%D0%BA%D0%BE%D0%B2-%D0%9F%D0%BE%D0%B4%D0%BF%D0%B8%D1%81%D0%B0%D1%82%D1%8C%D1%81%D1%8F-0088cc)](https://github.com/mkfun/mkox)</a>

Простой говнокод файлосервак. Создано для MKFun.

## Компоненты

- **mkboxd** - HTTP сервер с Unix socket (ну вообще сокетом fr удобнее, не нужно порт открывать наружу) P.S. как таковой mboxd нет, все в одном бинаре, просто разными компонентами аля -daemon/-ctl
- **mkbox -ctl** - утилита управления сервером

## собрать

```bash
make
```

## юзать

### настроить

```bash
sudo ./mkbox -ctl init
```

### стартануть сервак

```bash
sudo ./mkbox -daemon
```
(btw лучше сразу service воткнуть)

### рулить

```bash
./mkbox -ctl list
./mkbox -ctl info <file_id>
./mkbox -ctl reset-token <file_id>
./mkbox -ctl delete <file_id>
```

(комманд больше, писать лень)

## Nginx

ну конфиг вроде тут валяется

## Docker

```bash
docker-compose up -d
```

(признаюсь, не тестил...)

## Systemd (Linux)

Системд вирус ааа, ладно, короч валяется .service, его в /etc/systemd/system/ и потом systemctl daemon-reload и systemctl start mkbox

## API

### авторизация

```bash
curl -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"key": "your_master_key"}'
```

### загрузка файла

```bash
curl -X POST http://localhost:8080/upload \
  -H "Authorization: Bearer your_token" \
  -F "file=@example.txt"
```

### скачивание файла

```bash
curl -H "Authorization: Bearer your_token" \
  http://localhost:8080/files/file_id
```
