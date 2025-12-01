<?php
/**
 * Plugin Name: Login
 * Description: Login con redirección por rol
 * Version: 1.0.0
 * Author: Inecxus
 */
if ( ! defined('ABSPATH') ) exit;

/* ============ CONFIG RÁPIDA ============ */
$LLR_CFG = [
  'login_slug'        => 'login-legal',        // página con [legal_login]
  'admin_panel_path'  => '/panel-administrador/',  // slug real
  'client_panel_path' => '/panel-cliente/',        // slug real
  'hide_admin_bar'    => true,
  'debug'             => false,                     // pon false cuando quede OK
  // logo
  'logo_url'          => 'https://legalengineering-ca.com/wp-content/uploads/2025/11/LEGAL-LOGO-1-scaled.png',
  'logo_alt'          => 'LEGAL ENGINEERING',
  'logo_size'         => 85,
];
/* ====================================== */

register_activation_hook(__FILE__, function () {
    if ( ! get_role('cliente') ) add_role('cliente', 'Cliente', ['read'=>true]);
});

/* ===== Helpers ===== */
function llr_cfg($key){ global $LLR_CFG; return $LLR_CFG[$key] ?? null; }
function llr_is_admin_like($user){
    if ( ! $user || is_wp_error($user) ) return false;
    return user_can($user, 'manage_options') || in_array('administrator', (array)$user->roles, true);
}
function llr_url_login(){  return home_url( '/'. trim(llr_cfg('login_slug'), '/').'/' ); }
function llr_url_admin(){  return home_url( llr_cfg('admin_panel_path') ); }
function llr_url_client(){ return home_url( llr_cfg('client_panel_path') ); }

function llr_here(){
    $u = $_SERVER['REQUEST_URI'] ?? '/';
    $p = parse_url($u, PHP_URL_PATH);
    return rtrim($p ?: '/', '/') . '/';
}
function llr_path($url){
    $p = parse_url($url, PHP_URL_PATH);
    return rtrim($p ?: '/', '/') . '/';
}
function llr_log($msg){ if ( llr_cfg('debug') ) error_log('[LLR] '.$msg); }

/* Redirección a prueba de headers (fallback meta+JS si ya hubo salida) */
function llr_safe_go($url){
    $dest = llr_path($url);
    $here = llr_here();
    if ($dest === $here) return; // evitar auto-redirect
    // no cache
    nocache_headers();
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');

    if ( ! headers_sent() ){
        wp_safe_redirect($url);
        exit;
    }
    // Fallback si algún tema/plugin ya envió salida
    echo '<!doctype html><meta http-equiv="refresh" content="0;url='.esc_attr($url).'">'
       . '<script>location.replace("'.esc_js($url).'")</script>'
       . '<a href="'.esc_attr($url).'">Continuar</a>';
    exit;
}

/* ===== No cache en login y paneles ===== */
add_action('template_redirect', function(){
    $targets = [
        '/'. trim(llr_cfg('login_slug'), '/') . '/',
        llr_cfg('admin_panel_path'),
        llr_cfg('client_panel_path'),
        '/wp-login.php',
    ];
    $here = llr_here();
    foreach ($targets as $t){
        $t = rtrim($t, '/') . '/';
        if ($here === $t || is_user_logged_in()){
            nocache_headers();
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
            break;
        }
    }
}, 0);

/* ===== Shortcode [legal_login] ===== */
add_shortcode('legal_login', function(){
    $is_rest  = defined('REST_REQUEST') && REST_REQUEST;
    $is_ajax  = wp_doing_ajax();
    $in_admin = is_admin();
    $can_flow = ! $is_rest && ! $is_ajax && ! $in_admin; // sólo front

    $msg = '';

    // procesar login
    if ( $can_flow && isset($_POST['llr_login_nonce']) && wp_verify_nonce($_POST['llr_login_nonce'], 'llr_login') ) {
        $raw_login = isset($_POST['llr_user']) ? trim(wp_unslash($_POST['llr_user'])) : '';
        $password  = isset($_POST['llr_pass']) ? (string) $_POST['llr_pass'] : '';

        // si usó email, conviértelo a user_login real
        if ( is_email($raw_login) ) {
            $by_email = get_user_by('email', $raw_login);
            if ( $by_email ) { $raw_login = $by_email->user_login; }
        }

        $user_obj = get_user_by('login', $raw_login);
        $is_client = $user_obj && ! llr_is_admin_like($user_obj);

        if ( $is_client ) {
            if ( ! preg_match('/^[A-Za-z]{3}-\d{3}$/', $raw_login) ) {
                $msg = '<div class="llr-alert">El usuario debe tener el formato AAA-000.</div>';
                llr_log('login blocked: invalid client username format for "'.$raw_login.'"');
            } elseif ( strlen($password) !== 8 ) {
                $msg = '<div class="llr-alert">La contraseña debe tener exactamente 8 caracteres.</div>';
                llr_log('login blocked: invalid client password length for "'.$raw_login.'"');
            }
        }

        if ( ! $msg ) {
            $creds = [
                'user_login'    => $raw_login,
                'user_password' => $password,
                'remember'      => false,
            ];

            $user = wp_signon($creds, is_ssl()); // <- clave: usa protocolo real

            if ( is_wp_error($user) ) {
                $msg = '<div class="llr-alert">Usuario o contraseña inválidos.</div>';
                llr_log('signon error: '.$user->get_error_message().' | supplied="'.$creds['user_login'].'"');
            } else {
                $target = llr_is_admin_like($user) ? llr_url_admin() : llr_url_client();
                llr_log('signon OK user='.$user->user_login.' roles='.implode(',', $user->roles).' -> '.$target);
                llr_safe_go($target);
            }
        }
    }

    // si ya está logueado y viene al login, sácalo (en front)
    if ( is_user_logged_in() ) {
        $u = wp_get_current_user();
        $t = llr_is_admin_like($u) ? llr_url_admin() : llr_url_client();
        llr_log('already logged: '.$u->user_login.' -> '.$t);
        if ($can_flow){ llr_safe_go($t); }
        return '<p style="padding:12px;background:#eef5ff;border:1px solid #cde;">Ya has iniciado sesión. En el front se redirige a <code>'.esc_html(llr_path($t)).'</code>.</p>';
    }

    // Debug visible
    $debug_box = '';
    if ( llr_cfg('debug') ) {
        $debug_box = '<div style="margin:10px 0;padding:8px;border:1px dashed #cbd5e1;background:#f8fafc;color:#333;font-size:12px">
        DEBUG: here='.esc_html(llr_here()).' | login_slug="/'.esc_html(trim(llr_cfg('login_slug'),'/')).'/" | admin="'.esc_html(llr_cfg('admin_panel_path')).'" | client="'.esc_html(llr_cfg('client_panel_path')).'"
        </div>';
    }

    $logo  = trim((string) llr_cfg('logo_url'));
    $alt   = esc_attr((string) llr_cfg('logo_alt'));
    $lsize = intval(llr_cfg('logo_size'));

    ob_start(); ?>
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800&family=Poppins:wght@400;600&display=swap');
    :root{
        --llr-dark:#42041a;
        --llr-primary:#68092b;
        --llr-accent:#d2ae6d;
        --llr-accent-2:#b29f59;
        --llr-accent-3:#bb985c;
    }
    .llr-viewport{ min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--llr-dark); font-family:'Montserrat', 'Poppins', sans-serif; }
    html,body{height:100%}
    .llr-wrap{width:100%;max-width:420px;border-radius:14px;background:linear-gradient(145deg, rgba(178,159,89,0.12), rgba(210,174,109,0.18));box-sizing:border-box;box-shadow:0 18px 35px rgba(0,0,0,0.35);}
    .llr-card{background:var(--llr-primary);border-radius:14px 14px 0 0;color:#fff;text-align:center;padding:28px 18px;border:1px solid rgba(210,174,109,0.35);border-bottom:0;}
    .llr-logo{width:<?php echo $lsize; ?>px;height:auto;margin:0 auto 12px;display:flex;align-items:center;justify-content:center;overflow:hidden}
    .llr-logo img{width:100%;height:100%;object-fit:contain;filter:drop-shadow(0 6px 12px rgba(0,0,0,0.35));}
    .llr-body{background:#0f0109;border:1px solid rgba(210,174,109,0.35);border-top:0;border-radius:0 0 14px 14px;padding:22px 18px 12px;color:#e8e6e3;}
    .llr-label{font-size:12px;font-weight:700;color:var(--llr-accent);margin:10px 0 6px;letter-spacing:0.03em;}
    .llr-input{width:100%;padding:12px 14px;border:1px solid rgba(210,174,109,0.45);border-radius:10px;background:rgba(187,152,92,0.08);color:#f6f4f2;}
    .llr-input::placeholder{color:#c9bfa5;font-family:'Poppins', sans-serif;}
    .llr-btn{width:100%;padding:13px 14px;margin:18px 0 12px;border:0;border-radius:12px;background:linear-gradient(135deg, var(--llr-accent-2), var(--llr-accent-3));color:#2c241f;font-weight:800;cursor:pointer;font-family:'Montserrat', sans-serif;box-shadow:0 12px 22px rgba(0,0,0,0.25);}
    .llr-btn:hover{filter:brightness(0.93)}
    .llr-alert{background:rgba(255,236,236,0.12);color:#f8d7da;padding:12px 14px;border-radius:8px;margin-bottom:8px;border:1px solid rgba(255,173,173,0.35)}
    .llr-small{text-align:center;font-size:11px;color:#c9bfa5;padding:12px;font-family:'Poppins', sans-serif;}
    </style>

    <div class="llr-viewport">
      <div class="llr-wrap">
        <div class="llr-card">
            <?php if ($logo): ?>
                <div class="llr-logo"><img src="<?php echo esc_url($logo); ?>" alt="<?php echo $alt; ?>"></div>
            <?php endif; ?>
            <h2 style="margin:0 0 6px;font-family:'Montserrat',sans-serif;letter-spacing:0.04em">LEGAL ENGINEERING</h2>
            <p style="margin:0;color:var(--llr-accent);font-family:'Poppins',sans-serif">Ingrese sus credenciales para acceder</p>
        </div>
        <div class="llr-body">
            <?php echo $debug_box; ?>
            <?php echo $msg; ?>
            <form method="post" action="">
                <?php wp_nonce_field('llr_login','llr_login_nonce'); ?>
                <label class="llr-label">USUARIO</label>
                <input class="llr-input" type="text" name="llr_user" placeholder="Ingrese su usuario o email" required>
                <label class="llr-label">CONTRASEÑA</label>
                <input class="llr-input" type="password" name="llr_pass" placeholder="Ingrese su contraseña" required>
                <button class="llr-btn" type="submit">INGRESAR</button>
            </form>
        </div>
        <div class="llr-small">© 2025 LEGAL ENGINEERING</div>
      </div>
    </div>
    <?php
    return ob_get_clean();
});

/* ===== por si usan /wp-login.php: tras login ir a panel por rol ===== */
add_filter('login_redirect', function($redirect_to, $requested, $user){
    if ( is_wp_error($user) || ! $user ) return $redirect_to;
    $t = llr_is_admin_like($user) ? llr_url_admin() : llr_url_client();
    llr_log('login_redirect -> '.$t);
    return $t;
}, 10, 3);

/* ===== proteger paneles y bloquear /wp-admin según rol ===== */
add_action('template_redirect', function(){
    $here       = llr_here();
    $admin_path = rtrim(llr_cfg('admin_panel_path'), '/') . '/';
    $client_path= rtrim(llr_cfg('client_panel_path'), '/') . '/';

    if ( in_array($here, [$admin_path, $client_path], true) ) {
        if ( ! is_user_logged_in() ) {
            llr_log('panel access without login -> login');
            llr_safe_go( llr_url_login() );
        }

        $user = wp_get_current_user();
        if ( $here === $admin_path && ! llr_is_admin_like($user) ) {
            llr_log('panel admin blocked for non admin -> client panel');
            llr_safe_go( llr_url_client() );
        }
        if ( $here === $client_path && llr_is_admin_like($user) ) {
            llr_log('panel client blocked for admin -> admin panel');
            llr_safe_go( llr_url_admin() );
        }
    }
}, 5);

/* ===== bloquear /wp-admin a clientes (sin afectar REST/AJAX) ===== */
add_action('admin_init', function(){
    if ( ! is_user_logged_in() ) return;
    if ( wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST) ) return;
    $user = wp_get_current_user();
    if ( is_admin() && ! llr_is_admin_like($user) ) {
        $t = llr_url_client(); llr_log('block wp-admin -> '.$t); llr_safe_go($t);
    }
});

/* ===== ocultar barra de admin en front ===== */
add_action('after_setup_theme', function(){
    if ( ! is_user_logged_in() ) return;
    if ( llr_cfg('hide_admin_bar') ) {
        show_admin_bar(false);
    }
});

/* ===== shortcode [legal_logout label="Cerrar sesión"] ===== */
add_shortcode('legal_logout', function($atts){
    $atts = shortcode_atts(['label'=>'Cerrar sesión','class'=>'llr-logout-btn'], $atts, 'legal_logout');
    $url = wp_logout_url( llr_url_login() );
    return '<a href="'.esc_url($url).'" class="'.esc_attr($atts['class']).'">'.$atts['label'].'</a>';
});

/* estilo mínimo del botón de logout (opcional) */
add_action('wp_head', function(){
    echo '<style>.llr-logout-btn{display:inline-block;padding:10px 14px;border-radius:8px;background:#e2e8f0;color:#1f2937;text-decoration:none;font-weight:600}
.llr-logout-btn:hover{filter:brightness(0.95)}</style>';
});
