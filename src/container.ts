import { Container } from "eldin";

/**
 * Shared dependency injection container for `@peculiar/x509`.
 *
 * Register custom algorithm providers or signature formatters against this
 * instance to extend the library's behaviour.
 */
export const container = new Container();
