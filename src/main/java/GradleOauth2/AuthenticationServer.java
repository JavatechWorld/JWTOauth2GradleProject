/*
 * package GradleOauth2;
 * 
 * import org.eclipse.jetty.server.Server; import
 * org.eclipse.jetty.servlet.ServletContextHandler; import
 * org.eclipse.jetty.servlet.ServletHolder;
 * 
 * 
 * public class AuthenticationServer { public static void main(String[] args)
 * throws Exception { ServletContextHandler context = new
 * ServletContextHandler(ServletContextHandler.SESSIONS);
 * context.setContextPath("/api");
 * 
 * Server jettyServer = new Server(7070); jettyServer.setHandler(context);
 * 
 * ServletHolder jerseyServlet =
 * context.addServlet(org.glassfish.jersey.servlet.ServletContainer.class,
 * "/*"); jerseyServlet.setInitOrder(0);
 * 
 * jerseyServlet.setInitParameter("jersey.config.server.provider.classnames",
 * Calculator.class.getCanonicalName());
 * 
 * try { jettyServer.start(); jettyServer.join(); } finally {
 * jettyServer.destroy(); } } }
 */