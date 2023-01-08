#[macro_export]
macro_rules! debug {
  ($($arg:tt)*) => {
      if *NSS_HTTP_API_DEBUG {
          println!("NSS_HTTP DEBUG: {}", format_args!($($arg)*))
      }
  };
  () => {

  };
}