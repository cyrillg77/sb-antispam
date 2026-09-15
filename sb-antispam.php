<?php
/**
 * Plugin Name: SB AntiSpam & Captcha
 * Description: Captcha mathématique + honeypot + jeton cookie + liste noire d'emails/domaines (dont domaines jetables) pour commentaires, inscription, WooCommerce, Contact Form 7, Elementor Pro Forms, Forminator et Ninja Forms. Équivalent WordPress du module PrestaShop "AntiSpam and Captcha".
 * Version: 1.2.2
 * Author: StarBoost
 * Text Domain: sb-antispam
 */

if (!defined('ABSPATH')) exit;

final class SB_AntiSpam
{
    const VERSION    = '1.2.2';
    const UPDATE_URL = 'https://raw.githubusercontent.com/cyrillg77/sb-antispam/main/info.json'; // mises à jour via GitHub (dépôt public)
    const OPT   = 'sb_antispam';
    const LOG   = 'sb_antispam_log';
    const COOKIE = 'sbcs';
    const TTL   = 3600; // validité du captcha (s)

    private static $instance;
    private $conf;

    public static function instance() { return self::$instance ?: (self::$instance = new self()); }

    private function __construct()
    {
        $this->conf = wp_parse_args((array) get_option(self::OPT, []), [
            'comment_form'  => 1,
            'register_form' => 1,
            'login_form'    => 0,
            'woo_login'     => 0,
            'woo_register'  => 1,
            'woo_checkout'  => 1,
            'cf7'           => 1,
            'elementor'     => 1,
            'forminator'    => 1,
            'ninja'         => 1,
            'captcha'       => 1,
            'ban_emails'    => '',
            'ban_domains'   => '',
            'disposable'    => 1,
            'message'       => 'Merci de résoudre cette opération',
        ]);

        add_action('init',           [$this, 'set_cookie']);
        // Endpoint non cachable : les champs (jeton + captcha) sont rechargés en JS, même si la page HTML est en cache
        add_action('rest_api_init', function () {
            register_rest_route('sb-antispam/v1', '/fields', [
                'methods' => 'GET', 'permission_callback' => '__return_true',
                'callback' => function () {
                    $this->set_cookie();
                    $r = new WP_REST_Response(['html' => $this->fields_html()]);
                    $r->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
                    return $r;
                },
            ]);
        });
        add_action('wp_head',        [$this, 'front_css']);
        add_action('wp_footer',      [$this, 'front_js']);

        // Commentaires
        if ($this->conf['comment_form']) {
            add_action('comment_form_after_fields',   [$this, 'render_fields']);
            add_action('comment_form_logged_in_after', [$this, 'render_fields']);
            add_filter('pre_comment_on_post', function ($post_id) {
                $err = $this->validate('comment', $_POST['email'] ?? '');
                if ($err) wp_die(esc_html($err), 403);
                return $post_id;
            });
        }
        // Connexion wp-login.php (brute force) : captcha + honeypot obligatoires, sinon la connexion est refusée même avec le bon mot de passe
        if ($this->conf['login_form']) {
            add_action('login_form',   [$this, 'render_fields']);
            add_action('login_head',   [$this, 'front_css']);
            add_action('login_footer', [$this, 'front_js']);
            add_filter('authenticate', function ($user, $username) {
                // Uniquement le POST du formulaire wp-login.php (pas XML-RPC, REST, WooCommerce ni cookie auth)
                if (($GLOBALS['pagenow'] ?? '') !== 'wp-login.php' || empty($_POST['log']) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)) return $user;
                if ($e = $this->validate('login', '')) return new WP_Error('sb_antispam', $e);
                return $user;
            }, 30, 2); // priorité 30 : APRÈS wp_authenticate_username_password (20), qui ignore un WP_Error reçu en amont et renverrait quand même l'utilisateur
        }
        // Connexion WooCommerce (Mon compte)
        if ($this->conf['woo_login']) {
            add_action('woocommerce_login_form', [$this, 'render_fields']);
            add_filter('woocommerce_process_login_errors', function ($err) {
                if ($e = $this->validate('woo-login', '')) $err->add('sb_antispam', $e);
                return $err;
            });
        }
        // Inscription WP
        if ($this->conf['register_form']) {
            add_action('register_form', [$this, 'render_fields']);
            add_filter('registration_errors', function ($errors, $login, $email) {
                if ($e = $this->validate('register', $email)) $errors->add('sb_antispam', $e);
                return $errors;
            }, 10, 3);
        }
        // WooCommerce — inscription (page Mon compte)
        if ($this->conf['woo_register']) {
            add_action('woocommerce_register_form', [$this, 'render_fields']);
            add_filter('woocommerce_registration_errors', function ($errors, $login, $email) {
                // Ce filtre se déclenche aussi lors d'une création de compte au checkout : on laisse le checkout gérer
                if (defined('WOOCOMMERCE_CHECKOUT') || !empty($_POST['woocommerce-process-checkout-nonce'])) return $errors;
                if ($e = $this->validate('woo-register', $email)) $errors->add('sb_antispam', $e);
                return $errors;
            }, 10, 3);
        }
        // WooCommerce — checkout classique (shortcode), invités compris
        if ($this->conf['woo_checkout']) {
            add_action('woocommerce_review_order_before_submit', [$this, 'render_fields']);
            add_action('woocommerce_after_checkout_validation', function ($data, $errors) {
                if ($e = $this->validate('woo-checkout', $data['billing_email'] ?? '')) $errors->add('sb_antispam', $e);
            }, 10, 2);
        }
        // Contact Form 7
        if ($this->conf['cf7']) {
            add_filter('wpcf7_form_elements', function ($html) {
                return preg_replace('/(<input[^>]*type="submit")/i', $this->fields_html() . '$1', $html, 1);
            });
            add_filter('wpcf7_spam', function ($spam, $submission) {
                if ($spam) return $spam;
                $data  = $submission->get_posted_data();
                $email = $data['your-email'] ?? ($data['email'] ?? '');
                if ($e = $this->validate('cf7', $email)) {
                    $submission->add_spam_log(['agent' => 'sb-antispam', 'reason' => $e]);
                    return true;
                }
                return false;
            }, 10, 2);
        }

        // Elementor Pro Forms (champs injectés en JS, validation serveur)
        if ($this->conf['elementor']) {
            add_action('elementor_pro/forms/validation', function ($record, $ajax_handler) {
                $email = '';
                foreach ($record->get('fields') as $f) if (($f['type'] ?? '') === 'email') { $email = $f['value']; break; }
                if ($e = $this->validate('elementor', $email)) $ajax_handler->add_error_message($e);
            }, 10, 2);
        }
        // Forminator
        if ($this->conf['forminator']) {
            add_filter('forminator_custom_form_submit_errors', function ($errors, $form_id, $fields) {
                $email = '';
                foreach ((array) $fields as $f) if (strpos($f['name'] ?? '', 'email-') === 0) { $email = $f['value']; break; }
                if ($e = $this->validate('forminator', $email)) $errors[] = $e;
                return $errors;
            }, 10, 3);
        }

        // Ninja Forms : envoi AJAX en JSON, nos champs sont recopiés dans formData.extra côté JS
        if ($this->conf['ninja']) {
            add_filter('ninja_forms_submit_data', function ($form_data) {
                foreach (['sb_url','sb_cs','sb_answer','sb_ts','sb_sig'] as $k) if (!isset($_POST[$k])) $_POST[$k] = $form_data['extra'][$k] ?? '';
                $email = ''; $email_id = null; $first_id = null;
                foreach ((array) ($form_data['fields'] ?? []) as $f) {
                    $first_id = $first_id ?? $f['id'];
                    $field = Ninja_Forms()->form($form_data['id'])->get_field($f['id']);
                    if ($field && $field->get_setting('type') === 'email') { $email = $f['value']; $email_id = $f['id']; break; }
                }
                if ($e = $this->validate('ninja', $email)) {
                    // Ninja ne bloque de façon fiable que sur une erreur de champ : on l'accroche à l'email (ou au 1er champ)
                    $form_data['errors']['fields'][$email_id ?? $first_id] = $e;
                    $form_data['errors']['form']['sb_antispam'] = $e;
                }
                return $form_data;
            });
        }

        // Mises à jour auto-hébergées (starboost.fr) : WP affiche la MAJ dans Extensions comme n'importe quel plugin
        add_filter('pre_set_site_transient_update_plugins', [$this, 'check_update']);
        add_action('delete_site_transient_update_plugins', function () { delete_transient('sb_antispam_update'); }); // « Vérifier à nouveau » force aussi notre vérification
        add_filter('plugins_api', [$this, 'plugin_info'], 10, 3);

        add_action('admin_menu', [$this, 'admin_menu']);
        add_action('admin_post_sb_antispam_save', [$this, 'admin_save']);
    }

    /* ---------- Front ---------- */

    public function set_cookie()
    {
        if (!empty($_COOKIE[self::COOKIE]) || headers_sent()) return;
        $token = wp_generate_password(32, false);
        setcookie(self::COOKIE, $token, time() + DAY_IN_SECONDS, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);
        $_COOKIE[self::COOKIE] = $token;
    }

    private function cookie() { return sanitize_text_field($_COOKIE[self::COOKIE] ?? ''); }

    public function fields_html()
    {
        $h  = '<div class="sb-as">';
        // Honeypot : champ caché via CSS, un humain ne le remplit jamais
        $h .= '<input type="text" name="sb_url" class="sb-hp" value="" tabindex="-1" autocomplete="off">';
        // Jeton cookie : doit correspondre au cookie posé (bots sans cookie = rejet)
        $h .= '<input type="hidden" name="sb_cs" value="' . esc_attr($this->cookie()) . '">';
        if ($this->conf['captcha']) {
            $a = random_int(1, 12); $b = random_int(1, 12); $ts = time();
            $sig = $this->sign($a + $b, $ts);
            $h .= '<p class="sb-captcha"><label>' . esc_html($this->conf['message']) . ' : <strong>' . $a . ' + ' . $b . ' =</strong> '
                . '<input type="number" name="sb_answer" required inputmode="numeric" style="width:5em"></label>'
                . '<input type="hidden" name="sb_ts" value="' . $ts . '">'
                . '<input type="hidden" name="sb_sig" value="' . esc_attr($sig) . '"></p>';
        }
        return $h . '</div>';
    }

    public function render_fields() { echo $this->fields_html(); }

    private function sign($answer, $ts) { return hash_hmac('sha256', $answer . '|' . $ts, wp_salt('nonce')); }

    public function front_css() { echo '<style>.sb-hp{position:absolute!important;left:-9999px!important;opacity:0;height:0;width:0}</style>'; }

    public function front_js()
    {
        // Injection JS pour les formulaires AJAX (Elementor, Forminator) : les champs partent dans le POST avec le reste.
        $targets = [];
        if ($this->conf['elementor'])  $targets[] = ['form.elementor-form', '.elementor-field-type-submit'];
        if ($this->conf['forminator']) $targets[] = ['form.forminator-custom-form', '.forminator-button-submit'];
        if ($this->conf['ninja'])      $targets[] = ['.nf-form-content', '.submit-container'];
        ?>
        <script>
        (function(){
            var html = null, T = <?php echo wp_json_encode($targets); ?>;
            // Champs récupérés via REST (jamais en cache) : évite jeton périmé si la page est servie par WP Rocket / LiteSpeed / Cloudflare
            fetch(<?php echo wp_json_encode(rest_url('sb-antispam/v1/fields')); ?>, {credentials:'same-origin', cache:'no-store'})
              .then(function(r){ return r.json(); }).then(function(d){
                html = d.html;
                document.querySelectorAll('.sb-as').forEach(function(b){ b.outerHTML = html; }); // rafraîchit les blocs rendus côté serveur
                inject();
                new MutationObserver(inject).observe(document.body, {childList:true, subtree:true}); // popups Elementor, formulaires chargés en AJAX
              });
            function inject(){
                if (!html) return;
                T.forEach(function(t){
                    document.querySelectorAll(t[0]).forEach(function(f){
                        if (f.querySelector('.sb-as')) return;
                        var btn = f.querySelector(t[1]), w = document.createElement('div'); w.innerHTML = html;
                        btn ? btn.parentNode.insertBefore(w.firstChild, btn) : f.appendChild(w.firstChild);
                    });
                });
            }
            // Ninja Forms : on greffe nos champs directement sur la requête AJAX jQuery (nf_ajax_submit) → arrivent en $_POST
            if (window.jQuery) jQuery.ajaxPrefilter(function(options){
                if (typeof options.data !== 'string' || options.data.indexOf('action=nf_ajax_submit') === -1) return;
                var m = decodeURIComponent(options.data).match(/"id"\s*:\s*"?(\d+)/),
                    box = (m && document.querySelector('#nf-form-' + m[1] + '-cont .sb-as')) || document.querySelector('.nf-form-cont .sb-as');
                if (!box) return;
                box.querySelectorAll('input').forEach(function(i){ options.data += '&' + i.name + '=' + encodeURIComponent(i.value); });
            });
        })();
        </script>
        <?php
    }

    /* ---------- Validation ---------- */

    public function validate($form, $email)
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $email = sanitize_email($email);

        // 1. Honeypot
        if (!empty($_POST['sb_url'])) return $this->fail("Honeypot rempli [$form] $ip $email");
        // 2. Jeton cookie
        if (empty($_POST['sb_cs']))
            return $this->fail("Jeton absent du POST (champs non transmis par le form builder) [$form] $ip $email");
        if (!$this->cookie())
            return $this->fail("Cookie absent (page servie depuis un cache ?) [$form] $ip $email");
        if (!hash_equals($this->cookie(), sanitize_text_field($_POST['sb_cs'])))
            return $this->fail("Jeton != cookie (HTML mis en cache) [$form] $ip $email");
        // 3. Captcha (signé HMAC : stateless, non falsifiable côté client)
        if ($this->conf['captcha']) {
            $ans = (int) ($_POST['sb_answer'] ?? -1); $ts = (int) ($_POST['sb_ts'] ?? 0); $sig = $_POST['sb_sig'] ?? '';
            if (time() - $ts > self::TTL || !hash_equals($this->sign($ans, $ts), $sig))
                return $this->fail("Captcha incorrect [$form] $ip $email", 'Vérification de sécurité échouée.');
        }
        // 4. Listes noires
        if ($email && is_email($email)) {
            $domain = strtolower(substr(strrchr($email, '@'), 1));
            if (in_array(strtolower($email), $this->list('ban_emails'), true))
                return $this->fail("Email banni [$form] $ip $email");
            if (in_array($domain, $this->list('ban_domains'), true))
                return $this->fail("Domaine banni [$form] $ip $email");
            if ($this->conf['disposable'] && $this->is_disposable($domain))
                return $this->fail("Domaine jetable [$form] $ip $email");
        }
        return '';
    }

    private function fail($log, $msg = 'Une erreur est survenue lors de la validation du formulaire.')
    {
        $logs = (array) get_option(self::LOG, []);
        array_unshift($logs, current_time('mysql') . ' — ' . $log);
        update_option(self::LOG, array_slice($logs, 0, 300), false);
        return $msg;
    }

    private function list($key)
    {
        return array_filter(array_map('strtolower', array_map('trim', preg_split('/[\s,;]+/', $this->conf[$key]))));
    }

    // Liste stockée hors du dossier plugin (wp-content/uploads/sb-antispam/) : une MAJ du plugin ne l'écrase jamais
    private function list_file()
    {
        $dir = wp_upload_dir()['basedir'] . '/sb-antispam';
        if (!is_dir($dir)) { wp_mkdir_p($dir); file_put_contents("$dir/.htaccess", "Deny from all\n"); }
        $file = "$dir/disposable-domains.txt";
        if (!file_exists($file)) copy(plugin_dir_path(__FILE__) . 'disposable-domains.txt', $file); // seed à la 1re activation
        return $file;
    }

    private function is_disposable($domain)
    {
        $file = $this->list_file();
        if (!file_exists($file)) return false;
        static $set = null;
        if ($set === null) $set = array_flip(array_map('trim', file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
        return isset($set[$domain]);
    }

    /* ---------- Mises à jour ---------- */

    private function remote_info()
    {
        if (($info = get_transient('sb_antispam_update')) !== false) return $info;
        $r = wp_remote_get(self::UPDATE_URL, ['timeout' => 10]);
        $info = (!is_wp_error($r) && wp_remote_retrieve_response_code($r) === 200) ? json_decode(wp_remote_retrieve_body($r)) : null;
        set_transient('sb_antispam_update', $info ?: 0, 12 * HOUR_IN_SECONDS);
        return $info;
    }

    public function check_update($transient)
    {
        $info = $this->remote_info();
        if ($info && version_compare(self::VERSION, $info->version, '<')) {
            $transient->response[plugin_basename(__FILE__)] = (object) [
                'slug' => 'sb-antispam', 'plugin' => plugin_basename(__FILE__),
                'new_version' => $info->version, 'package' => $info->download_url, 'url' => 'https://starboost.fr',
            ];
        }
        return $transient;
    }

    public function plugin_info($res, $action, $args)
    {
        if ($action !== 'plugin_information' || ($args->slug ?? '') !== 'sb-antispam') return $res;
        $info = $this->remote_info(); if (!$info) return $res;
        return (object) [
            'name' => 'SB AntiSpam & Captcha', 'slug' => 'sb-antispam', 'version' => $info->version, 'author' => 'StarBoost',
            'download_link' => $info->download_url, 'sections' => ['changelog' => $info->changelog ?? ''],
        ];
    }

    /* ---------- Admin ---------- */

    public function admin_menu()
    {
        add_options_page('SB AntiSpam', 'SB AntiSpam', 'manage_options', 'sb-antispam', [$this, 'admin_page']);
    }

    public function admin_save()
    {
        check_admin_referer('sb_antispam');
        if (!current_user_can('manage_options')) wp_die();
        if (isset($_POST['clear_logs'])) { delete_option(self::LOG); }
        elseif (isset($_POST['update_disposable'])) { $this->update_disposable_list(); }
        else {
            $c = [];
            foreach (['comment_form','register_form','login_form','woo_login','woo_register','woo_checkout','cf7','elementor','forminator','ninja','captcha','disposable'] as $k) $c[$k] = empty($_POST[$k]) ? 0 : 1;
            $c['ban_emails']  = sanitize_textarea_field($_POST['ban_emails'] ?? '');
            $c['ban_domains'] = sanitize_textarea_field($_POST['ban_domains'] ?? '');
            $c['message']     = sanitize_text_field($_POST['message'] ?? '');
            update_option(self::OPT, $c);
        }
        wp_safe_redirect(admin_url('options-general.php?page=sb-antispam&saved=1')); exit;
    }

    private function update_disposable_list()
    {
        $r = wp_remote_get('https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf', ['timeout' => 30]);
        if (!is_wp_error($r) && wp_remote_retrieve_response_code($r) === 200) {
            // Fusion avec la liste existante (jamais de perte)
            $file = $this->list_file();
            $cur  = file_exists($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $new  = preg_split('/\R/', trim(wp_remote_retrieve_body($r)));
            $all  = array_unique(array_filter(array_map('trim', array_merge($cur, $new))));
            sort($all);
            file_put_contents($file, implode("\n", $all) . "\n");
        }
    }

    public function admin_page()
    {
        $c = $this->conf; $logs = (array) get_option(self::LOG, []);
        $file = $this->list_file();
        $cb = function ($k, $label) use ($c) {
            echo '<label><input type="checkbox" name="' . $k . '" value="1" ' . checked($c[$k], 1, false) . '> ' . $label . '</label><br>';
        };
        ?>
        <div class="wrap"><h1>SB AntiSpam & Captcha</h1>
        <?php if (!empty($_GET['saved'])) echo '<div class="notice notice-success"><p>Enregistré.</p></div>'; ?>
        <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
            <?php wp_nonce_field('sb_antispam'); ?><input type="hidden" name="action" value="sb_antispam_save">
            <table class="form-table">
                <tr><th>Formulaires protégés</th><td>
                    <?php $cb('comment_form', 'Commentaires'); $cb('register_form', 'Inscription WordPress'); $cb('login_form', 'Connexion wp-login.php'); $cb('woo_login', 'Connexion WooCommerce (Mon compte)'); $cb('woo_register', 'Inscription WooCommerce (Mon compte)'); $cb('woo_checkout', 'Checkout WooCommerce classique (shortcode)'); $cb('cf7', 'Contact Form 7'); $cb('elementor', 'Elementor Pro Forms'); $cb('forminator', 'Forminator'); $cb('ninja', 'Ninja Forms'); ?>
                </td></tr>
                <tr><th>Captcha mathématique</th><td><?php $cb('captcha', 'Activer (sinon : honeypot + jeton uniquement)'); ?>
                    <input type="text" name="message" class="regular-text" value="<?php echo esc_attr($c['message']); ?>"></td></tr>
                <tr><th>Emails bannis</th><td><textarea name="ban_emails" rows="5" class="large-text" placeholder="un par ligne"><?php echo esc_textarea($c['ban_emails']); ?></textarea></td></tr>
                <tr><th>Domaines bannis</th><td><textarea name="ban_domains" rows="5" class="large-text" placeholder="ex: spam.ru"><?php echo esc_textarea($c['ban_domains']); ?></textarea></td></tr>
                <tr><th>Domaines jetables</th><td><?php $cb('disposable', 'Bloquer les adresses jetables'); ?>
                    <?php echo file_exists($file) ? count(file($file)) . ' domaines en base (' . date('d/m/Y', filemtime($file)) . ')' : 'Liste non téléchargée'; ?>
                    <button class="button" name="update_disposable" value="1">Mettre à jour la liste</button></td></tr>
            </table>
            <?php submit_button(); ?>
            <h2>Journal (<?php echo count($logs); ?>)</h2>
            <button class="button" name="clear_logs" value="1">Vider</button>
            <pre style="background:#fff;padding:10px;max-height:400px;overflow:auto"><?php echo esc_html(implode("\n", $logs)); ?></pre>
        </form></div>
        <?php
    }
}

SB_AntiSpam::instance();
