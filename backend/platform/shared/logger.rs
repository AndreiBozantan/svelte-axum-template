#[macro_export]
macro_rules! log_error {
    ($module:expr, $context:expr, $error:expr $(, $key:ident = $val:expr)* $(,)?) => {
        tracing::error!(
            module = $module,
            context = $context,
            error = %$error,
            $($key = ?$val,)*
        )
    };
}

#[macro_export]
macro_rules! log_warning {
    ($module:expr, $context:expr, $error:expr $(, $key:ident = $val:expr)* $(,)?) => {
        tracing::warn!(
            module = $module,
            context = $context,
            error = %$error,
            $($key = ?$val,)*
        )
    };
}

#[macro_export]
macro_rules! log_info {
    ($module:expr, $context:expr $(, $key:ident = $val:expr)* $(,)?) => {
        tracing::info!(
            module = $module,
            context = $context,
            $($key = ?$val,)*
        )
    };
}

pub use log_error;
pub use log_info;
pub use log_warning;