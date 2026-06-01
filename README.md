# Решение
## Номер 1
### Задание
Как запустить nmap для 30 000 ip-адресов оптимально быстрого поиска по всем живых хостов по всем портам с выводом версией ПО. Расписать ответ и зачем выбрано каждое значение.
### Ответ
Сканирование 30 000 хостов по всем 65 535 портам с определением версий ПО nmap'ом будет проводиться слишком долго. Я бы сначала определил "живые хосты", например masscan'ом 
```
sudo masscan -p1-65535 -iL targets.txt --rate 100000 -oG live_hosts.txt
```
* -p1-65535 - все порты
* -iL targets.txt - список всех адресов
* --rate 10000 - 100000 пакетов в секунду
* -oG live_hosts.txt - вывод в Grepable формат 

Это займет значительно меньше времени, после чего, для каждого хоста будет получен список открытых на нем портов.

Далее, можно распарсить файл и получить список всех уникальных адресов, на которых открыт, хотя бы один порт, а затем запустить nmap только по ним. 

```
# Получение уникальных живых хостов
grep "^Timestamp:" live_hosts.txt | awk '{print $4}' | sort -u > alive_hosts.txt

# Сканируем только живые хосты
sudo nmap -sV -p- -iL alive_hosts.txt -T4 --max-retries 2 -oA nmap_detailed
```

Для большей оптимизации, можно парсить файл в скрипте, например на питоне и запускать сканирование для каждого хоста только по окрытым на нем портам.

## Номер 2
### Задание
Каким способом будете искать все http/ https приложения и впоследствии все поддеректории этого приложения?
### Ответ
1. Произведу сканирование по всем известным ip-адресам приложения.
    ```
    nmap -sS -p 80,443 --open -iL targets.txt -oG web_ports.gnmap
    ```
    Таким образом, можно отсеять те адреса, на которых закрыты http и https порты.
2. К каждой из комбинаций IP-адрес + открытый порт отправлю GET-запрос для обнаружения всех рабочих http-сервисов
3. К тем портам, от которых получены ответы 200, 301/302, 403 применю фаззеры, например, ffuf для обнаружения директорий

## Номер 3
### Задание
Задача: сканировать большую инфраструктуру и оповестить при обнаружении опубликованного приложения с уязвимостью log4shell. Какие команды будете выполнять для данной задачи? Как это можно автоматизировать? 
### Ответ
Для обнаружения уязвимости log4shell при сканировании инфраструктуры можно использовать сканеры nmap и nuclei. 
1. Обнаружение открытых веб-сервисов для уменьшения поверхности
    ```
    nmap -sS -p 80,443,8080,8443,9090 --open -iL targets.txt -oG services.gnmap
    ```
    * -sS - быстрое syn-сканирование
    * -p 80,443,8080,8443,9090 - сканирует только указанные порты
        * 80/tcp - http серверы
        * 443/tcp - https серверы
        * 8080/tcp - Альтернативный HTTP для Java-приложений 
        * 8443/tcp - Альтернативный HTTPS для Java-приложений 
        * 9090/tcp - различные дашборды
    * --open - выводит только хосты с хотя бы 1 открытым портом из приведенных
    (Если настроены другие порты - нужно указать их при сканировании)
2. Активное обнаружение log4shell 
    ```
    nuclei -t http/vulnerabilities/log4j/ -l nuclei_targets.txt -json-export results.json
    ```
    * -t http/vulnerabilities/log4j/ - Загружает шаблоны проверки Log4Shell из оф. репозитория ProjectDiscovery
    * -l nuclei_targets.txt - Список целей, полученных после фильтрации вывода nmap'a
3. Парсинг и фильтрация json'а, полученного от nuclei
4. Настройка оповещения (например, от SIEM/SOAR ...)
```
# Пример отправки в SIEM (Splunk HEC / Elastic / Graylog)
curl -s -X POST "https://siem.internal/api/v1/events" \
  -H "Authorization: Bearer ${SIEM_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @deduplicated.jsonl
```
5. Для автоматизации данного пайплайна можно запланировать выполнение задач по расписанию, например, через crontab

## Номер 4
### Задание
Указан ip адрес 130.193.51.48. Задача найти все домены и субдомены которые есть на этом ip адресcе. Какие команды будете выполнять для данной задачи? Где искать? Как это можно автоматизировать? 
### Ответ
1. Посмотрел данные об адресе на shodan.io и censys.io - не нашел информацию о доменах, только об открытых портах и AS.
2. Сделал 
    ```
    whois 130.193.51.48
    dig -x 130.193.51.48 +short
    nslookup 130.193.51.48  
    host 130.193.51.48    
    ```
    Но, не получил информации о доменах, только подтверждение, что адрес связан с облаком яндекса.
3. Сделал 
    ```
    curl -Ik http://130.193.51.48:<port>
    ```
    Для каждого порта, обнаруженного шоданом. "Живым" оказаллся только порт 9100, на котором работал Prometheus Node Exporter. Его изучение не дало результатов (я не углублялся, т.к. не был уверен в правомерности).
4. Можно провести сканирование фаззером, чтобы определить поддомены, например, используя ffuf:
    ```
    # обнаружение api
    ffuf -u http://130.193.51.48/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/
    # обнаружение самых частых поддоменов
    ffuf -u http://130.193.51.48/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt    
    ```
    Т.к. я не знаю, что это за сервис и кому он принадлежит, я не стал проводить фаззинг, т.к. это может быть не совсем законно (272 УК РФ).
Весь процесс можно автоматизиорвать. В python, используя библиотеку beuatiful soup можно парсить html-ответы, чтобы доставать из них необхоимую информацию. Конольные же утилиты можно вызывать, используя модуль subprocess. Домены, полученные из shodan и censys, а также, утилит можно использовать для поиска поддоменов, например, используя TheHarvester. Если это не даст результатов - тогда, можно использовать ffuf или dirbuster

## Номер 5
### Задание
Сканер уязвимости выдал уязвимость CVE-2021-45046, опишите ваши дальнейшие действия чтобы доказать эксплуатируемость этой уязвимости в инфраструктуре заказчика.
### Ответ

Информация с NIST:
```
Base Score:  9.0 CRITICAL
Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H
```
Уязвимость есть в каталоге CISA KEV
Расшифровка:
* Вектор атаки: сеть
* Сложность атаки: высокая
* Требуемые привелегии: нет
* Нет неоходимости в действии пользователя
* Атака переходит с одной машины на другую
* Высокая опасность для Конфиденциальности, целостности и доступности информации
План:
1. Неоходимо изучить уязимость. Это критическая уязвимость в библиотеке Apache Log4j, которая позволяет злоумышленникам внедрять вредоносные данные через JNDI (Java Naming and Directory Interface) Lookup-шаблоны, что может привести к утечке информации, удалённому или локальному выполнению кода.
2. Необходимо проанализировать архитектуру заказчика. Уязвимость неэксплуатруема, если у уязвимого сервера, например, нет доступа к внешним ресурсам. 
3. Необходимои изучить конфигурацию уязвимого сервера - определить, используются ли уязвимые версии библиотеки, есть ли в конфигурационных уязвимые строчки, в случае white-box тестирования.
4. Провести проверку на целевой системе или ее копии, используя безопасный payload, чтобы не нарушать работу сервиса. 
5. По ходу выполнения необходимо документировать весь ход работы, все запросы, доказательства успешной эксплуатации, после чего, предоставить заказчику.



## Номер 6
### Задание
Дан отчет по одной машине (quest1.csv), требуется указать порядок устранения уязвимостей. Хорошо бы структурировать найденные уязвимости. Указать ход мысли и метод решения.
### Ответ
При приоритезации, разумным будет ориентироваться не только на оценку риска cvss, но и на специфику уязвимости. При своей оценке я принимал во внимание вектор атаки и необходимые привилегии. 
1. В первую очередь, необходимо решить самые опасные уязвимости: те, у которых высокая оценка (high или critical), эксплуатируются через внешнюю сеть и отсутствуют необходимые привелегии.
2. Далее, необходимо перейти к ликвидации остальных уязвимостей, начиная с самых опасных из оставшихся. Кроме оценки cvss, можно ориентироаться на то, сколько уязвимостей покрываются исправлениями пакетов данной уязвимости. Таким образом, исправлением одной уязвимости можно покрыть сразу множество других.
Для решения данной задачи написал код на python который анализирует csv файл и выводит уязвимости и в порядке, описанном выше.   
\
\
Уязвимости, которые необходимо ликвидировать в первую очередь
```
top
        CVE-2019-14895      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-14896      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-14897      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-14901      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-15505      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-16746      9.8         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-17133      9.8         Packages: 3       Full Cover: 381     Part Cover: 294
        CVE-2020-27068      9.8         Packages: 2       Full Cover: 121     Part Cover: 177
        CVE-2022-37434      9.8         Packages: 2       Full Cover: 2       Part Cover: 0
        CVE-2019-10220      8.8         Packages: 2       Full Cover: 121     Part Cover: 177
        CVE-2019-11815      8.1         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-6974       8.1         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2016-5244       7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2018-16871      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2018-5390       7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2018-5391       7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-10639      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-11477      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-11478      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-11479      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-11810      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-17075      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-19049      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-19052      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-19074      7.5         Packages: 3       Full Cover: 381     Part Cover: 294
        CVE-2019-19078      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-19768      7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2019-8980       7.5         Packages: 1       Full Cover: 176     Part Cover: 201
        CVE-2020-25672      7.5         Packages: 5       Full Cover: 266     Part Cover: 781
        CVE-2021-23840      7.5         Packages: 2       Full Cover: 8       Part Cover: 0
        CVE-2022-2795       7.5         Packages: 5       Full Cover: 10      Part Cover: 0
        CVE-2022-36946      7.5         Packages: 2       Full Cover: 121     Part Cover: 177
        CVE-2020-25705      7.4         Packages: 7       Full Cover: 958     Part Cover: 335
        CVE-2021-20322      7.4         Packages: 2       Full Cover: 121     Part Cover: 177
        CVE-2021-3712       7.4         Packages: 2       Full Cover: 8       Part Cover: 0
        CVE-2023-0286       7.4         Packages: 2       Full Cover: 8       Part Cover: 0
```
Кроме обозначения cvss, ее оценки, выводятся:
* Packages - количество пакетов, в которых найдена уязвимость 
* Full Cover - количество уязвимостей, которые частично покрываются исправлением пакетов данной уязвимости
* Part Cover - количество уязвимостей, которые полностью покрываются исправлением пакетов данной уязвимости

## Номер 7
### Задание
Вам пришла уязвимость, сделайте готовую инструкцию администратору для проверки (если требуется) и патчинга этой уязвимости. Указать ход мысли и метод решения.
### Ответ
Уязвимость:
```
kernel-uek-firmware@4.1.12 CVE-2019-17133 oracle-oval In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a long SSID IE, leading to a Buffer Overflow. Оценка 9.8 Critical CVSS3
```
CVE-2019-17133 - уязвимость в ядре операционной системы Linux, связанная с функцией cfg80211_mgd_wext_giwessid в файле net/wireless/wext-sme.c. В версиях ядра Linux до 5.3.2 функция не проверяет длину информационного элемента (IE) SSID, что приводит к переполнению буфера (Buffer Overflow). Эксплуатация уязвимости может позволить удалённому злоумышленнику выполнить произвольный код или вызвать отказ в обслуживании (сбой системы).

Эта уязвимость исправляется обновлением пакетов ядра. Судя по названию пакета kernel-uek-firmware, это oracle linux, можно написать конкретные командытпод систему.

Инструкция для администрации:
1. Предварительная оценка:
    
    * Проверить, есть ли у устройства беспроводной интерфейс? Интерфейса нет -> уязвимость нельзя эксплуатировать, но, лучше обновить пакеты
    ``` 
    ip a # посмотреть наличие wlan, wifi, 802.11, wlp...
    ```
    * Проверить установленную версию пакета
    ```
    rpm -q kernel-uek-firmware
    ```
    если действительно выводится kernel-uek-firmware-4.1.12 - уязвимость есть - нужно исправить
2. Обновить пакеты (перед обновлением рекомендуется сделать снапшот системы)
    
    * Обновить метаданные репозитория (Oracle Linux/ULN)
    ```
    sudo yum clean metadata
    sudo yum makecache
    ```
    * Обновить все пакеты или только уязвимый
    ```
    sudo yum update kernel-uek-firmware # только уязвимый пакет
    sudo yum update kernel-uek kernel-uek-firmware # полное обновление
    ```
3. Перезагрузить систему (рекомендуется после обновлений, обязательно после полного)
4. Верифицировать исправление
    * Проверить установленную версию пакета
    ```
    rpm -q kernel-uek-firmware
    ```
    если версия не содержит суффикс -124.54.6.1 и выше, уязвимость есть - нужно проверить подключение к репозиторию и повторить обновление 
    * Зафиксировать исправление в системе учета


## Номер 8
### Задание
Есть API https://demo.defectdojo.org/api/v2/oa3/swagger-ui/, проанализруйте API, какие запросы требуется выполнить, чтобы забрать все уязвимости по API в SIEM ?
### Ответ
В данной API, уязвимости можно получить по запросу /api/v2/findings/. При использовании этого запроса, можно задать параметры пагинации, фильтрации, получаемых уязвимостей, временных меток, активов и т.д.

Для получения данных в SIEM по запросу, необходимо: 
1. Авторизоваться по:
    * Логину / паролю
    * Ключу API
    * По токену авторизации
2. Настроить фильтрацию отображаемых уязвимостей (active, verified...).
3. Настроить пагинацию (limit, offset...).
4. Нормализовать данные под формат SIEM.
5. При необходимости, отладить процесс и настроить выгрузку по расписанию.

## Номер 9
### Задание
Web сканер выдал уязвимость. Что будете делать, чтобы проверить эту уязвимость, докажите ее эксплуатируемость и способы митигации или докажите ложность срабатывания.
### Ответ
```
Issue: Reflected XSS
POST https://www.target.ru/cat/detail/kovsh-tefal-l6502/page/1/?
show=response&sort_responses=date HTTP/1.1
accept-encoding: gzip, deflate
cache-control: no-cache
pragma: no-cache
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 
(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
content-type:
host: www. target.ru
content-length: 0
x-proxy-name: f5
accept-language: ru-RU,ru;q=0.9
authority: www. target.ru
http-sw-white: 0
referer: https://www.target.ru/
x-forwarded-proto: https
accept:
text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/
webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9
http-sw-ipcountry: RU
payloads:
1)
-unique_jxs0c901m3=1337//</style><svg/onload=unique_jxs0c901m3=1337//>/
**/unique_jxs0c901m3=1337//("-unique_jxs0c901m3=1337-"///,\'-
unique_jxs0c901m3=1337-\'--><svg/onload=unique_jxs0c901m3=1337>\x3csvg
onload=unique_jxs0c901m3=1337\x3e</textarea><svg/onload=unique_jxs0c901
m3=1337//>/**/unique_jxs0c901m3=1337//</
script><script>unique_jxs0c901m3=1337//function()
{{unique_jxs0c901m3=1337}}()*/unique_jxs0c901m3=1337--><svg/
onload=unique_jxs0c901m3=1337//>
2) javascript:unique_pkt6zxuzkbo=1337//*/javascript:javascript:"/*'/*`/*--></
noscript></title></textarea></style></template></noembed></script><html "
onmouseover=/*&lt;svg/*/onload=unique_pkt6zxuzkbo=1337onload=unique_pkt6
zxuzkbo=1337//><svg onload=unique_pkt6zxuzkbo=1337><svg
onload=unique_pkt6zxuzkbo=1337>*/</style><script>unique_pkt6zxuzkbo=133
7</script><style>
3) jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=unique_k82ci4a9ubr=1337
)//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/
oNloAd=unique_k82ci4a9ubr=1337//>\x3e
```

## Номер 10
### Задание
Web сканер выдал уязвимость. Что будете делать, чтобы проверить эту уязвимость, докажите ее эксплуатируемость и способы митигации или докажите ложность срабатывания.
### Ответ
```
Issue: NoSQL injection
GET https://guru.tagret.ru/?utm_source=main_footer HTTP/1.1
Host: guru.tagret.ru
vuln_params: {'utm_source': ["',", '$where:', "'1", '==', "1'", '1,', '$where:', "'1",
'==', "1'", '{', '$ne:', '1', '}', "',", '$or:', '[', '{},', '{', "'a':'a", "'", '}', '],',
"$comment:'successful", 'MongoDB', "injection'",
'db.injection.insert({success:1});', 'db.injection.insert({success:1});return',
'1;db.stores.mapReduce(function()', '{', '{', 'emit(1,1', '||', '1==1', "'", '&&', 
'this.password.match(/./)//+%00', "'", '&&', 'this.passwordzz.match(/./)//+%00',
"'%20%26%26%20this.password.match(/./)//+%00",
"'%20%26%26%20this.passwordzz.match(/./)//+%00", '{$gt:', "''}", '[$ne]=1',
'.*']}
```
1. Анализ уязвимости
   * Тип: NoSQL Injection (судя по выводу сканера, MongoDB)
   * Вектор: GET-параметр utm_source в запросе к guru.tagret.ru. Параметры utm_* почти всегда используются только для аналитики (отправка в Яндекс.Метрику, Google Analytics, логирование). Если параметр не попадает в запрос к БД — это 100% ложное срабатывание. Всегда начинайте с вопроса: «А зачем utm_source лезть в базу данных?»
   * Пейлоады: операторы MongoDB ($where, $ne, $or, $regex, $comment) + JS-инъекции
   
2. Валидация
    \
    Необходимо проверить, действительно ли utm_source попадает в запрос к базе данных. Если нет - сканер выдал ложное срабатывание.
    \
    Это можно проверить, передавая различные значения utm_score в запрос и сверяя результаты
    * Если utm_score действительно попадает в запрос - будут различия в ответах при разных подаваемых значениях
    ```
    # пример запросов для сравнения
    # результаты сходятся -> ложное срабатывание
    curl -s "https://guru.tagret.ru/?utm_source=test1"
    curl -s "https://guru.tagret.ru/?utm_source=test2"
    ```
    * Также, могут быть различия при "легитимном" и "инъекционном" значениях
    ```
    # пример запросов для сравнения
    # результаты сходятся -> ложное срабатывание
    curl -s "https://guru.tagret.ru/?utm_source=normal" -o normal.html
    curl -s "https://guru.tagret.ru/?utm_source=%24where:alert(1)"
    ```
    * Также, можно проверить логи. Если в них нет запросов к базе с этим параметром
    
    Для проверки на реальную инъекцию, начать с более простых инъекций, не тех, которые показаны в выдаче сканера - главное показать, что можно изменить логику запроса, а не извлекать данные или вызывать выполнение кода.
3. Ликвидация
    * Не передавать пользовательский ввод напрямую
    * Валидировать входные данные
    * Использовать параметризованные запросы
    * Минимизировать привелегии учетных записей пользователей
    * Добавить фильтрацию ввода пользователя на уровне WAF

## Номер 11
### Задание
Как бы выглядела инструкция для 1 линии? Что бы вы ей отдали и какие функции выполняли бы сами?
### Ответ (исходя из предположения, что это продолжение вопроса 10)
* Для первой линии: 
    1. Выполнить нормальный и инъекционный запросы, отметить, есть ли различия:
    ```
    # пример запросов для сравнения
    curl -s "https://guru.tagret.ru/?utm_source=normal" -o normal.html
    curl -s "https://guru.tagret.ru/?utm_source=%24where:alert(1)"
    ```
    2. Проверить исходный код (Ctrl+U):
    Отметить факт наличия/отсутствия в коде страницы строк "utm_source" или "normal".
    3. Проверить, не возвращает ли страница ошибки при запросах, изменяется ли время ответа
    
    Если нет ничего из перечисленного - ложное срабатывания
* Для аналитика:
    1. Проанализировать, каким должно быть легитимное поведение utm_source в коде
    2. Разработать точный proof-of-concept
    3. Интерпретировать смешанные результаты проверки первой линии
    4. Решить, как ликвидировать уязвимость - экранировать или валидировать пользовательский ввод
    5. Донести до разработччиков суть проблемы

## Номер 12
### Задание
qust2.csv Расскажите порядок исправления, было бы неплохо, если несколько уязвимостей разной степени критичности закрывались одним патчем (kb). И если бы некоторые уязвимости проще было бы проигнорировать (чем закрывать), это про вопрос принятия риска.
### Ответ
Приоритезация близка к той, что была предложена в 6-ом задании. Чем опаснее уязвимость и больше уязвимостей покрывает исправление ее патча - тем выше ее приоритет для исправления. Наиболее опасные уявимости выбираются так же.

Для достижения баланса между оценкой уязвимости и количеством исправлений при накатывания патча, была написана функция корреляции
```
priority = (CVSS_score - {9, 7, 4, 0} )^1.1 * (collateral fixes)
```  
Приоритетные уязвимости для исправления:
```
top
        CVE-2021-33749      8.8         patch fixes: 45 other vulnerabilities
        CVE-2021-33750      8.8         patch fixes: 45 other vulnerabilities
        CVE-2021-33752      8.8         patch fixes: 45 other vulnerabilities
        CVE-2021-33756      8.8         patch fixes: 45 other vulnerabilities
        CVE-2021-36970      8.8         patch fixes: 28 other vulnerabilities
        CVE-2021-34492      8.1         patch fixes: 45 other vulnerabilities
        CVE-2021-1678       8.8         patch fixes: 24 other vulnerabilities
        CVE-2021-40444      8.8         patch fixes: 24 other vulnerabilities
        CVE-2021-34446      8.0         patch fixes: 45 other vulnerabilities
        CVE-2021-34535      8.8         patch fixes: 22 other vulnerabilities
        CVE-2021-38666      8.8         patch fixes: 14 other vulnerabilities
        CVE-2021-26435      8.1         patch fixes: 24 other vulnerabilities
        CVE-2021-28319      7.5         patch fixes: 55 other vulnerabilities
        CVE-2021-28324      7.5         patch fixes: 55 other vulnerabilities
        CVE-2021-28439      7.5         patch fixes: 55 other vulnerabilities
        CVE-2021-43217      8.1         patch fixes: 23 other vulnerabilities
        CVE-2021-31977      8.6         patch fixes: 15 other vulnerabilities
        CVE-2021-31183      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-33772      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-33785      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-33788      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-34476      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-34490      7.5         patch fixes: 45 other vulnerabilities
        CVE-2021-36953      7.5         patch fixes: 28 other vulnerabilities
        CVE-2021-36960      7.5         patch fixes: 24 other vulnerabilities
        CVE-2021-43222      7.5         patch fixes: 23 other vulnerabilities
        CVE-2021-43228      7.5         patch fixes: 23 other vulnerabilities
        CVE-2021-43233      7.5         patch fixes: 23 other vulnerabilities
        CVE-2021-43236      7.5         patch fixes: 23 other vulnerabilities
        CVE-2021-26433      7.5         patch fixes: 22 other vulnerabilities
        CVE-2021-36926      7.5         patch fixes: 22 other vulnerabilities
        CVE-2021-36932      7.5         patch fixes: 22 other vulnerabilities
        CVE-2021-36933      7.5         patch fixes: 22 other vulnerabilities
        CVE-2021-31958      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-31968      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-31974      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-31975      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-31976      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-33742      7.5         patch fixes: 15 other vulnerabilities
        CVE-2021-41356      7.5         patch fixes: 14 other vulnerabilities
        CVE-2021-31186      7.4         patch fixes: 14 other vulnerabilities
        CVE-2021-38665      7.4         patch fixes: 14 other vulnerabilities
```

## Номер 13
### Задание
ports3.csv На какие порты вы бы обратили особое внимание и почему? Какой информации о порте вам не хватает? Как можно автоматизировать получение дополнительной информации по порту?
### Ответ
Для приоритезации я: 
* взял из интернета список самых критических служб и портов, на которых они работают, 
* написал код на python, который автоматически находит в csv-файле указанные порты и делит их по категориям

Порты, на которые следует обратить особое внимание:
```
critical
        port: 445       service: SMB
        port: 5432      service: PostgreSQL
        port: 9200      service: Elasticsearch
        port: 1433      service: MSSQL
        port: 80        service: HTTP
        port: 3306      service: MySQL
        port: 443       service: HTTPS
        port: 21        service: FTP
        port: 3389      service: RDP
        port: 22        service: SSH
        port: 8443      service: HTTPS-Alt
        port: 8080      service: HTTP-Alt
        port: 23        service: Telnet
high
        port: 389       service: LDAP
        port: 5900      service: VNC
        port: 8000      service: App servers
        port: 8007      service: App servers
        port: 8001      service: App servers
        port: 8002      service: App servers
        port: 8008      service: App servers
        port: 8009      service: App servers
        port: 9090      service: Webmin/Cockpit
        port: 9418      service: Git
        port: 636       service: LDAPS
        port: 25        service: SMTP
        port: 1521      service: Oracle DB
        port: 53        service: DNS
        port: 111       service: RPC (portmapper)
        port: 135       service: MSRPC
        port: 139       service: NetBIOS
medium
        port: 587       service: SMTP Submission
        port: 993       service: IMAPS
        port: 995       service: POP3S
        port: 8888      service: Jupyter/alt HTTP
        port: 873       service: Rsync
        port: 1723      service: PPTP
        port: 2049      service: NFS
        port: 10000     service: Webmin
        port: 5061      service: SIP (VoIP)
        port: 179       service: BGP
        port: 5060      service: SIP (VoIP)
```
Для полноты картины не достает следующей информации о портах:
  * Работающий сервис
  * Версия ПО
  * Используется ли шифрование SSL/TLS ?
  * Используется ли аутентификация
  * Сетевая зона
  * Статус сервиса (active/stale)

Для автоматизации процеса можно собрать список всех портов из списка и использовать алгоритм, приведенный в задании 1 для определения всей недостающей информации

