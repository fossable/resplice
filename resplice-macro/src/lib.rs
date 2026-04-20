use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Expr, ItemFn, Lit, Meta};

/// Marks a function as a replacement for a section of binary code.
///
/// # Arguments
///
/// * `begin` - The starting address of the code to replace
/// * `end` - The ending address of the code to replace
///
/// # Example
///
/// ```ignore
/// #[Splice(begin = 0x1670, end = 0x1680)]
/// fn add_one_plus_one() -> i32 {
///     1 + 1
/// }
/// ```
#[proc_macro_attribute]
pub fn Splice(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);

    // Parse arguments manually
    let meta_list = parse_macro_input!(args with syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated);

    let mut begin_addr: Option<u64> = None;
    let mut end_addr: Option<u64> = None;

    for meta in meta_list {
        if let Meta::NameValue(nv) = meta {
            let name = nv.path.get_ident().map(|i| i.to_string());

            match name.as_deref() {
                Some("begin") => {
                    if let Expr::Lit(expr_lit) = nv.value {
                        if let Lit::Int(lit_int) = expr_lit.lit {
                            begin_addr = lit_int.base10_parse().ok();
                        }
                    }
                }
                Some("end") => {
                    if let Expr::Lit(expr_lit) = nv.value {
                        if let Lit::Int(lit_int) = expr_lit.lit {
                            end_addr = lit_int.base10_parse().ok();
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let begin = begin_addr.expect("Splice attribute requires 'begin' parameter");
    let end = end_addr.expect("Splice attribute requires 'end' parameter");

    let fn_name = &input_fn.sig.ident;
    let fn_name_str = fn_name.to_string();
    let vis = &input_fn.vis;
    let sig = &input_fn.sig;
    let block = &input_fn.block;

    // Generate the function with metadata
    let expanded = quote! {
        #[no_mangle]
        #[link_section = ".splice"]
        #vis #sig {
            #block
        }

        // Register this splice in the inventory
        ::splice::inventory::submit! {
            ::splice::SpliceMetadata {
                function_name: #fn_name_str,
                begin_addr: #begin,
                end_addr: #end,
            }
        }
    };

    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote;
    use syn::parse_quote;

    #[test]
    fn test_quote_expansion() {
        let fn_name_str = "test_fn";
        let begin: u64 = 0x1000;
        let end: u64 = 0x2000;

        let expanded = quote! {
            ::splice::SpliceMetadata {
                function_name: #fn_name_str,
                begin_addr: #begin,
                end_addr: #end,
            }
        };

        let expanded_str = expanded.to_string();
        assert!(expanded_str.contains("test_fn"));
        assert!(expanded_str.contains("0x1000"));
        assert!(expanded_str.contains("0x2000"));
    }

    #[test]
    fn test_address_parsing_logic() {
        use syn::punctuated::Punctuated;

        let meta_list: Punctuated<Meta, syn::Token![,]> =
            parse_quote!(begin = 0x1000, end = 0x2000);

        let mut begin_addr: Option<u64> = None;
        let mut end_addr: Option<u64> = None;

        for meta in meta_list {
            if let Meta::NameValue(nv) = meta {
                let name = nv.path.get_ident().map(|i| i.to_string());

                match name.as_deref() {
                    Some("begin") => {
                        if let Expr::Lit(expr_lit) = nv.value {
                            if let Lit::Int(lit_int) = expr_lit.lit {
                                begin_addr = lit_int.base10_parse().ok();
                            }
                        }
                    }
                    Some("end") => {
                        if let Expr::Lit(expr_lit) = nv.value {
                            if let Lit::Int(lit_int) = expr_lit.lit {
                                end_addr = lit_int.base10_parse().ok();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        assert_eq!(begin_addr, Some(0x1000));
        assert_eq!(end_addr, Some(0x2000));
    }
}
