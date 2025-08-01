<?php

return [
    'title' => 'Ustawienia',
    'save_success' => 'Ustawienia zostały zapisane',
    'save_failed' => 'Nie udało się zapisać ustawień',
    'navigation' => [
        'general' => 'Ogólne',
        'captcha' => 'Captcha',
        'mail' => 'Mail',
        'backup' => 'Kopia zapasowa',
        'oauth' => 'OAuth',
        'misc' => 'Różne',
    ],
    'general' => [
        'app_name' => 'Nazwa aplikacji',
        'app_logo' => 'Logo aplikacji',
        'app_logo_help' => 'Logo powinno być umieszczone w folderze publicznym znajdującym się w katalogu głównym panelu. Pozostaw puste, aby zamiast tego użyć nazwy aplikacji.',
        'app_favicon' => 'Favicon aplikacji',
        'app_favicon_help' => 'Favicon powinien być umieszczony w folderze publicznym, znajdującym się w katalogu głównym.',
        'debug_mode' => 'Tryb debugowania',
        'navigation' => 'Nawigacja',
        'sidebar' => 'Pasek boczny',
        'topbar' => 'Pasek górny',
        'unit_prefix' => 'Prefiks jednostki',
        'decimal_prefix' => 'Prefiks dziesiętny (MB/GB)',
        'binary_prefix' => 'Prefiks binarny (MiB/GiB)',
        '2fa_requirement' => 'Wymóg 2FA',
        'not_required' => 'Niewymagane',
        'admins_only' => 'Wymagane tylko dla administratorów',
        'all_users' => 'Wymagane dla wszystkich użytkowników',
        'trusted_proxies' => 'Zaufane proxy',
        'trusted_proxies_help' => 'Nowe IP lub zakres IP',
        'clear' => 'Wyczyść',
        'set_to_cf' => 'Ustaw na adresy IP Cloudflare',
        'display_width' => 'Szerokość wyświetlania',
        'avatar_provider' => 'Dostawca awataru',
        'uploadable_avatars' => 'Zezwolić użytkownikom na ustawianie własnego awataru?',
    ],
    'captcha' => [
        'enable' => 'Włącz',
        'disable' => 'Wyłącz',
        'info_label' => 'Info',
        'info' => 'Możesz wygenerować klucze na swoim <u><a href="https://developers.cloudflare.com/turnstile/get-started/#get-a-sitekey-and-secret-key" target="_blank">Panelu Cloudflare</a></u>. Wymagane jest konto Cloudflare.',
        'site_key' => 'Klucz strony',
        'secret_key' => 'Sekretny Klucz',
        'verify' => 'Zweryfikować domenę?',
    ],
    'mail' => [
        'mail_driver' => 'Sposób wysyłania wiadomości e-mail',
        'test_mail' => 'Wyślij e-mail testowy',
        'test_mail_sent' => 'Mail testowy wysłany',
        'test_mail_failed' => 'Wiadomość testowa nie powiodła się',
        'from_settings' => 'Z ustawień',
        'from_settings_help' => 'Ustaw adres i nazwę używaną jako "Nadawca" w wiadomościach e-mail.',
        'from_address' => 'Z adresu',
        'from_name' => 'Nadawca',
        'smtp' => [
            'smtp_title' => 'Konfiguracja SMTP',
            'host' => 'Host',
            'port' => 'Port',
            'username' => 'Nazwa użytkownika',
            'password' => 'Hasło',
            'scheme' => 'Schemat',
        ],
        'mailgun' => [
            'mailgun_title' => 'Konfiguracja Mailgun',
            'domain' => 'Domena',
            'secret' => 'Sekret',
            'endpoint' => 'Punkt końcowy',
        ],
    ],
    'backup' => [
        'backup_driver' => 'Sterownik kopii zapasowej',
        'throttle' => 'Ograniczenia',
        'throttle_help' => 'Skonfiguruj, ile kopii zapasowych może zostać utworzonych w danym okresie. Ustaw okres na 0, aby wyłączyć to ograniczenie.',
        'limit' => 'Limit',
        'period' => 'Okres',
        'seconds' => 'Sekundy',
        's3' => [
            's3_title' => 'Konfiguracja S3',
            'default_region' => 'Domyślny region',
            'access_key' => 'Identyfikator klucza dostępu',
            'secret_key' => 'Sekretny klucz dostępu',
            'bucket' => 'Bucket',
            'endpoint' => 'Punkt końcowy',
            'use_path_style_endpoint' => 'Użyj Endpoint w stylu ścieżki.',
        ],
    ],
    'oauth' => [
        'enable' => 'Włącz',
        'disable' => 'Wyłącz',
        'client_id' => 'Identyfikator Klienta',
        'client_secret' => 'Sekret klienta',
        'redirect' => 'Adres URL przekierowania',
        'web_api_key' => 'Klucz Web API',
        'base_url' => 'Podstawowy adres URL',
        'display_name' => 'Wyświetlana nazwa',
        'auth_url' => 'Adres URL zwrotnego wywołania autoryzacji',
    ],
    'misc' => [
        'auto_allocation' => [
            'title' => 'Automatyczne tworzenie alokacji',
            'helper' => 'Zmień ustawienie, jeśli użytkownicy mogą tworzyć alokacje za pomocą strefy klienta.',
            'question' => 'Zezwalać użytkownikom na tworzenie alokacji?',
            'start' => 'Port początkowy',
            'end' => 'Port końcowy',
        ],
        'mail_notifications' => [
            'title' => 'Powiadomienia e-mail',
            'helper' => 'Wybierz, które powiadomienia mailowe mają być wysyłane do użytkowników.',
            'server_installed' => 'Serwer zainstalowany',
            'server_reinstalled' => 'Serwer został ponownie zainstalowany',
        ],
        'connections' => [
            'title' => 'Połączenia',
            'helper' => 'Czasy oczekiwania używane podczas wysyłania żądań.',
            'request_timeout' => 'Upłynął Limit czasu żądania',
            'connection_timeout' => 'Przekroczenie limitu czasu połączenia',
            'seconds' => 'Sekundy',
        ],
        'activity_log' => [
            'title' => 'Dziennik aktywności',
            'helper' => 'Skonfiguruj, jak często stare dzienniki aktywności powinny być usuwane oraz czy aktywności administratorów powinny być rejestrowane.',
            'prune_age' => 'Okres przechowywania przed usunięciem',
            'days' => 'Dni',
            'log_admin' => 'Ukryj działania administratora?',
        ],
        'api' => [
            'title' => 'API',
            'helper' => 'Określa limit liczby żądań na minutę, które mogą zostać wykonane.',
            'client_rate' => 'Limit API klienta',
            'app_rate' => 'Limit API aplikacji',
            'rpm' => 'Zapytania na minutę',
        ],
        'server' => [
            'title' => 'Serwery',
            'helper' => 'Ustawienia serwerów',
            'edit_server_desc' => 'Zezwolić użytkownikom na edycję opisów?',
            'console_font_upload' => 'Prześlij Czcionkę Konsoli',
            'console_font_hint' => 'Obsługiwane są tylko czcionki *.ttf. Mocno zalecamy czcionki Mono!',
        ],
        'webhook' => [
            'title' => 'Webhooki',
            'helper' => 'Skonfiguruj, jak często stare logi webhooków powinny być usuwane.',
            'prune_age' => 'Wyczyść Wiek',
            'days' => 'Dni',
        ],
    ],
];
