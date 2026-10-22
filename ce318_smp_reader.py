"""
Скрипт для чтения данных с трехфазного счетчика (CE318) 
по протоколу SMP поверх TCP (через ser2net).

--- КАК УСТРОЕН ПРОТОКОЛ (для новичков) ---
1. СЕТЬ: Мы подключаемся к IP:ПОРТ по TCP. 
2. КАДР: Данные передаются кадрами (пакетами). Начало и конец кадра — 
   байт 0xC0.
3. ЭКРАНИРОВАНИЕ: Если внутри данных встречается 0xC0 или 0xDB, мы их 
   заменяем на спец. последовательности (байт-стаффинг), чтобы приемник 
   не подумал, что пакет закончился раньше времени.
4. CRC: В конце пакета передается контрольная сумма.
   Если при передаче байты исказились, CRC не сойдется, и мы 
   отбросим этот пакет.
5. DFF: Счетчик экономит место. Числа передаются не целыми байтами, 
   а кусочками по 7 бит. 8-й (старший) бит каждого байта — это флаг:
   "1" - читай дальше, "0" - число закончилось.
"""

import socket
import struct
import time
import argparse
import math
import json
import sys


# ==============================================================================
# 1. БАЗОВЫЕ ФУНКЦИИ ПРОТОКОЛА
# ==============================================================================

def hexdump(data: bytes, prefix: str = ""):
    """
    Красиво выводит байты на экран 
    Слева смещение, в центре HEX-коды, справа — текст (ASCII).
    """
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        # Переводим байты в hex-строку (например, b'\x0A' -> "0A")
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Переводим байты в символы (если это читаемый текст)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        # Выводим в поток ошибок (stderr), чтобы не ломать JSON в консоли
        print(f"{prefix}{i:04X}: {hex_part:<48} |{ascii_part}|", file=sys.stderr)

def crc16(data: bytes) -> int:
    """
    Считает контрольную сумму (CRC16) для проверки целостности пакета.
    Полином 0x8005, начальное значение 0. 
    """
    crc = 0
    for b in data:
        crc ^= (b << 8) & 0xFFFF  # XOR с текущим байтом, сдвинутым влево
        for _ in range(8):        # Прогоняем каждый бит
            if crc & 0x8000:      # Если старший бит 1...
                crc = ((crc << 1) ^ 0x8005) & 0xFFFF
            else:                 # Иначе просто сдвигаем
                crc = (crc << 1) & 0xFFFF
    return crc

def escape(data: bytes) -> bytes:
    """
    Байт-стаффинг (экранирование).
    байт 0xC0 означает "начало/конец пакета".
    Заменяем его на два байта: 0xDB 0xDC. 
    """
    out = bytearray()
    for b in data:
        if b == 0xC0:
            out += b'\xDB\xDC'
        elif b == 0xDB:
            out += b'\xDB\xDD'
        else:
            out.append(b)
    return bytes(out)

def unescape(data: bytes) -> bytes:
    """
    Обратное экранирование (раскодирование).
    Если видим 0xDB 0xDC, превращаем обратно в 0xC0.
    """
    out, i = bytearray(), 0
    while i < len(data):
        if data[i] == 0xDB and i + 1 < len(data):
            if data[i+1] == 0xDC:
                out.append(0xC0)
                i += 2
                continue
            elif data[i+1] == 0xDD:
                out.append(0xDB)
                i += 2
                continue
        out.append(data[i])
        i += 1
    return bytes(out)

def dff_decode(data: bytes, idx: int, signed: bool = False) -> tuple[int, int]:
    """
    Самая сложная часть. Чтение чисел из DFF-формата.
    Счетчик шлет числа кусками по 7 бит.
    Если 8-й бит (0x80) равен 1, значит, число продолжается в следующем байте.
    Если 0, значит, это последний кусок.
    
    Параметр signed (знаковое ли число): 
    Токи и напряжения всегда положительные.
    А вот реактивная мощность или углы могут быть отрицательными.
    Для отрицательных используется "дополнительный код".
    """
    v, sh = 0, 0
    start_idx = idx
    while True:
        b = data[idx]
        idx += 1
        # Берем младшие 7 бит (b & 0x7F) и сдвигаем их на нужную позицию (sh)
        v |= (b & 0x7F) << sh
        sh += 7
        # Если 8-й бит равен 0 (b & 0x80 == 0), значит, это конец числа
        if not (b & 0x80):
            break

    length = idx - start_idx
    if signed:
        # Если число заняло 10 байт, это 64-битное отрицательное число
        if length == 10:
            if v >= (1 << 63):
                v -= (1 << 64)
        # Для коротких чисел проверяем бит знака (0x40)
        elif b & 0x40:
            v -= (1 << sh)

    return v, idx

def build_frame(addr: int, flags5: int, const6: int, smp_cmd: int, smp_flags: int, data_bytes: bytearray) -> bytes:
    """
    Собирает пакет для отправки в счетчик по кусочкам:
    [0xC0] - старт
    [06] - версия протокола
    [Адрес 4 байта] - кому шлем (структура '<I' значит Little Endian, 4 байта)
    [Служебные байты и Команда]
    [Полезные данные (какие параметры хотим узнать)]
    [CRC 2 байта] - контрольная сумма
    [0xC0] - конец
    """
    payload = bytearray([0x06])                      # Версия протокола
    payload += struct.pack('<I', addr)               # Адрес устройства (Little Endian)
    payload += bytes([flags5, const6, smp_cmd, smp_flags]) # Флаги и команда
    payload += data_bytes                            # Полезная нагрузка
    
    crc = crc16(payload)                             # Считаем отпечаток
    payload += bytes([(crc >> 8) & 0xFF, crc & 0xFF]) # Добавляем CRC (сначала старший байт, потом младший)
    
    # Экранируем данные и оборачиваем в 0xC0
    return bytes([0xC0]) + escape(payload) + bytes([0xC0])

# ==============================================================================
# 2. СЕТЕВОЕ ВЗАИМОДЕЙСТВИЕ
# ==============================================================================

def send_recv(host: str, port: int, request: bytes, timeout: float = 3.0, raw: bool = False) -> tuple[bytes | None, int | None]:
    """
    Отправляет запрос и ждет ответ по TCP.
    Возвращает: (тело_ответа, адрес_ответившего_устройства)
    """
    try:
        # Создаем TCP-сокет. SOCK_STREAM означает TCP (надежная передача).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout) # Если ответа нет 3 секунды — выдаем ошибку
            s.connect((host, port)) # Подключаемся к ser2net
            
            if raw:
                print(f"\n--- ОТПРАВКА ЗАПРОСА ({len(request)} байт) ---", file=sys.stderr)
                hexdump(request, "  ")
                
            s.sendall(request) # Отправляем байты
            
            buf, t0 = bytearray(), time.time()
            # Ждем ответ максимум 2 секунды
            while time.time() - t0 < 2.0:
                try:
                    chunk = s.recv(1024) # Читаем порцию данных (до 1024 байт)
                    if not chunk:
                        break
                    buf.extend(chunk)
                    
                    # Ищем в буфере кадры, которые начинаются и заканчиваются на 0xC0
                    frames, start = [], -1
                    for i, b in enumerate(buf):
                        if b == 0xC0:
                            if start == -1:
                                start = i
                            elif i > start:
                                frames.append(bytes(buf[start:i+1]))
                                start = i
                                
                    for f in frames:
                        if raw:
                            print(f"\n--- ПОЛУЧЕН ОТВЕТ ({len(f)} байт) ---", file=sys.stderr)
                            hexdump(f, "  ")
                            
                        # Убираем 0xC0 по краям и раскодируем экранирование
                        body = unescape(f[1:-1])
                        # Проверяем CRC и минимальную длину (0x06 + 4 байта адреса + ...)
                        if len(body) > 8 and crc16(body[:-2]) == ((body[-2] << 8) | body[-1]):
                            # Если CRC сошлось — вытаскиваем адрес ответившего (байты 1-4)
                            resp_addr = struct.unpack('<I', body[1:5])[0]
                            if args.debug: print(f"CRC:",len(body) > 8 and crc16(body[:-2]),"==",((body[-2] << 8) | body[-1] ))
                            return body, resp_addr

                        else:
                            print(f"Ошибка CRC:",len(body) > 8 and crc16(body[:-2]),"!=",((body[-2] << 8) | body[-1] ))
                except socket.timeout:
                    break # Если таймаут — прерываем цикл ожидания
    except OSError as e:
        print(f"Ошибка сети: {e}", file=sys.stderr)
    return None, None

def parse_payload(body: bytes, expected_counts: dict, signed_codes: set = None) -> dict:
    """
    Разбирает данные, которые прислал счетчик.
    expected_counts: сколько чисел ждать для каждого кода. 
    Например, если просили токи по трем фазам, ждем 3 числа.
    signed_codes: какие коды могут быть отрицательными.
    """
    if signed_codes is None:
        signed_codes = set()

    smp_data = body[9:] # Пропускаем заголовок сетевого пакета (9 байт)
    idx = 0
    results = {}
    try:
        while idx < len(smp_data):
            # Читаем код параметра (например, 0x16 — это ток)
            code, idx = dff_decode(smp_data, idx, signed=False)
            # Если встретили код 0x04 — это конец данных
            if code in (0x04, 0x00) or code not in expected_counts:
                break
            
            count = expected_counts[code] # Сколько чисел ждем?
            vals = []
            is_signed = code in signed_codes # Может ли это число быть отрицательным?
            
            for _ in range(count):
                val, idx = dff_decode(smp_data, idx, signed=is_signed)
                vals.append(val)
            
            # Если значение одно, сохраняем как число, если несколько - как список
            results[code] = vals[0] if count == 1 else vals
    except IndexError:
        pass # Если данные кончились неожиданно, просто игнорируем
    return results

# ==============================================================================
# 3. ЛОГИКА СБОРА ДАННЫХ
# ==============================================================================

def fetch_all_data(host: str, port: int, req_addr: int = 0, raw: bool = False) -> dict:
    """
    Главная функция. Делает три запроса к счетчику и собирает всё в один словарь.
    """
    data = {
        "requested_address": f"{req_addr}",
        "responding_address": "none",
        "energy": {},
        "phases": {"A": {}, "B": {}, "C": {}},
        "total": {}
    }

    def query(req_data: bytes):
        """
        Вспомогательная функция для отправки запроса.
        Проверяет, совпадает ли адрес ответившего устройства с тем, что мы просили.
        """
        if args.debug: print("отправка req_data: ",req_data)
        body, resp_addr = send_recv(host, port, req_data, raw=raw)
        if args.debug: print("       прием Body: ",body)
        if args.debug: print("resp_addr: ",resp_addr)
        if args.debug: print(" req_addr: ",req_addr)
# Если мы просили конкретный адрес (не 0) и ответил кто-то другой или нет данных — это ошибка
        if resp_addr is None:
            return None, False
        data["responding_address"] = f"{resp_addr}"
        if req_addr != 0 and resp_addr != req_addr and not body:             
            return None, False        
        return body, True

    # --- ЗАПРОС 1: Накопленная энергия A+ ---
    # Байты [0x01, 0x02, 0x00]: код 0x01 (энергия), маска 0x02 (одно значение)
    req_energy = build_frame(req_addr, 0x00, 0x06, 0x0A, 0x00, bytearray([0x01, 0x02, 0x00]))
    body_energy, match = query(req_energy)

    if args.debug: print("energy match: ",match,"enaergy req: ", body_energy)
    
    if body_energy is None:
            data["energy"]={
            "error": "NO_DATA"
            }
    else:        
        res = parse_payload(body_energy, {0x01: 1})
        # Делим на 10000, так как энергия передается с 4 знаками после запятой
        data["energy"]["active_import_kwh"] = round(res.get(0x01, 0) / 10000.0, 4)

    # --- ЗАПРОС 2: Мгновенные значения по фазам ---
    # Байты [0x16, 0x1C, 0x18, 0x1C...]: 
    # 0x16 - ток, 0x18 - напряжение, 0x0D - полная мощность, 0x0E - активная, 0x10 - реактивная.
    # Маска 0x1C означает "верни данные для всех трех фаз".
    phase_req_data = bytearray([0x16, 0x1C, 0x18, 0x1C, 0x0D, 0x1C, 0x0E, 0x1C, 0x10, 0x1C, 0x04])
    req_phases = build_frame(req_addr, 0x00, 0x06, 0x0A, 0x00, phase_req_data)
    body_phases, match = query(req_phases)

    if args.debug: print("phases: ",match,"req: ",body_phases)
               
    if body_phases is None:
            data["phases"]={
            "error": "NO_DATA"
            }
    else:        
        # Ждем по 3 значения (Фазы A, B, C) для каждого кода.
        # Активная (0x0E) и реактивная (0x10) мощности могут быть отрицательными.
        phases = parse_payload(body_phases, {0x16: 3, 0x18: 3, 0x0D: 3, 0x0E: 3, 0x10: 3}, 
                               signed_codes={0x0E, 0x10})
        
        # Распределяем полученные массивы по фазам (0 - A, 1 - B, 2 - C)
        for i, phase_name in enumerate(["A", "B", "C"]):
            data["phases"][phase_name] = {
                "current_a": round(phases.get(0x16, [0,0,0])[i] / 1000.0, 4),
                "voltage_v": round(phases.get(0x18, [0,0,0])[i] / 100.0, 4),
                "power_total_kva": round(phases.get(0x0D, [0,0,0])[i] / 1000.0, 4),
                "power_active_kw": round(phases.get(0x0E, [0,0,0])[i] / 1000.0, 4),
                "power_reactive_kvar": round(phases.get(0x10, [0,0,0])[i] / 1000.0, 4),
            }

    # --- ЗАПРОС 3: Суммарные мощности ---
    # Маска 0x02 означает "верни одно суммарное значение".
    total_req_data = bytearray([0x0E, 0x02, 0x10, 0x02, 0x04])
    req_totals = build_frame(req_addr, 0x00, 0x06, 0x0A, 0x00, total_req_data)
    body_totals, match = query(req_totals)

    if args.debug: print("totat: ",match,"req: ",body_totals)  
       
    if body_totals is None:
            data["total"]={
            "error": "NO_DATA"
        }
    else:    
        totals = parse_payload(body_totals, {0x0E: 1, 0x10: 1}, signed_codes={0x0E, 0x10})
        p_act = totals.get(0x0E, 0) / 1000.0 # Активная (P)
        p_react = totals.get(0x10, 0) / 1000.0 # Реактивная (Q)
        
        # В трехфазной сети полная мощность (S) считается векторно: S = √(P² + Q²)
        s_total = math.sqrt(p_act**2 + p_react**2)
        
        data["total"] = {
            "power_active_kw": round(p_act, 4),
            "power_reactive_kvar": round(p_react, 4),
            "power_total_kva": round(s_total, 4)
        }

    # Если ни один запрос не увенчался успехом (нет связи)
    if data["responding_address"] == "none":
         return {"ERROR":{"requested_address": "none", "responding_address": "none", "error": "No response"}}

    return data

# ==============================================================================
# 4. ВЫВОД В ВИДЕ ТАБЛИЦЫ
# ==============================================================================

def print_table(data: dict) -> None:
    """
    Рисует красивую табличку с данными, чтобы можно было посмотреть глазами.
    """
    print("=" * 65)
    print(f" ЗАПРАШИВАЕМЫЙ АДРЕС: {data.get('requested_address', 'N/A')}")
    print(f" ОТВЕТИВШИЙ АДРЕС:    {data.get('responding_address', 'N/A')}")
    print("=" * 65)

    if "error" in data:
        print(f" ❌ ОШИБКА: {data['error']}")
        return

    print(f" Накопленная энергия A+: {data['energy'].get('active_import_kwh', 0):.4f} кВт·ч\n")

    print(f"{'Параметр':<22} | {'Фаза A':>10} | {'Фаза B':>10} | {'Фаза C':>10}")
    print("-" * 65)
    
    pA, pB, pC = data['phases']['A'], data['phases']['B'], data['phases']['C']
    
    print(f"{'Ток, А':<22} | {pA.get('current_a',0):>10.4f} | {pB.get('current_a',0):>10.4f} | {pC.get('current_a',0):>10.4f}")
    print(f"{'Напряжение, В':<22} | {pA.get('voltage_v',0):>10.4f} | {pB.get('voltage_v',0):>10.4f} | {pC.get('voltage_v',0):>10.4f}")
    print(f"{'Полная мощ., кВА':<22} | {pA.get('power_total_kva',0):>10.4f} | {pB.get('power_total_kva',0):>10.4f} | {pC.get('power_total_kva',0):>10.4f}")
    print(f"{'Активная мощ., кВт':<22} | {pA.get('power_active_kw',0):>10.4f} | {pB.get('power_active_kw',0):>10.4f} | {pC.get('power_active_kw',0):>10.4f}")
    print(f"{'Реактивная мощ., квар':<22} | {pA.get('power_reactive_kvar',0):>10.4f} | {pB.get('power_reactive_kvar',0):>10.4f} | {pC.get('power_reactive_kvar',0):>10.4f}")

    t = data['total']
    print("\n" + "=" * 65)
    print(" СУММАРНЫЕ МОЩНОСТИ (ВЕКТОРНАЯ СУММА)")
    print("=" * 65)
    print(f" Активная (P):   {t.get('power_active_kw',0):>8.4f} кВт")
    print(f" Реактивная (Q): {t.get('power_reactive_kvar',0):>8.4f} квар")
    print(f" Полная (S):     {t.get('power_total_kva',0):>8.4f} кВА")

# ==============================================================================
# 5. ТОЧКА ВХОДА
# ==============================================================================

if __name__ == "__main__":
    # Создаем парсер аргументов командной строки.
    # Это позволяет передавать настройки при запуске: python script.py --host 1.2.3.4
    parser = argparse.ArgumentParser(
        description="Чтение данных со счетчика SMP (протокол NNLC/SMP v6)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--host", default="192.168.1.123", help="IP-адрес сервера ser2net")
    parser.add_argument("--port", type=int, default=1234, help="TCP-порт ser2net")
    parser.add_argument("--addr", type=lambda x: int(x, 0), default=0, help="Сетевой адрес счетчика (0 - broadcast)")
    parser.add_argument("-t", "--table", action="store_true", help="Вывод в виде удобной таблицы, а не JSON")
    parser.add_argument("-r", "--raw", action="store_true", help="Выводить сырые hex-данные (запросы и ответы) в stderr")
    parser.add_argument("-d", "--debug", action="store_true", help="Выводить отладочный принт")
    
    args = parser.parse_args()

    # Получаем данные (вызываем главную функцию)
    data = fetch_all_data(args.host, args.port, args.addr, raw=args.raw)
    
    # Если пользователь просил таблицу — печатаем таблицу, иначе — JSON
    if args.table:
        print_table(data)
    else:
        # json.dumps с indent=4 делает JSON красивым (с отступами)
        print(json.dumps(data, indent=4, ensure_ascii=False))
