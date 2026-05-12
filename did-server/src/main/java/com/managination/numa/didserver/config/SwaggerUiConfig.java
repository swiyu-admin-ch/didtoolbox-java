package com.managination.numa.didserver.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.servlet.resource.PathResourceResolver;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

import java.io.IOException;
import java.util.List;
import java.util.Set;

/**
 * Spring configuration class that registers the Springwolf UI resources filter.
 * <p>
 * This configuration enables Springwolf UI to be served from the {@code /springwolf-ui} path
 * by intercepting requests and serving static resources from the classpath.
 * </p>
 *
 * @author Swiss Federal Chancellery
 */
@Configuration
public class SwaggerUiConfig {

   /**
    * Classpath prefix where Springwolf UI static resources are located.
    */
   private static final String SPRINGWOLF_UI_CLASSPATH = "/META-INF/resources/springwolf/";

    /**
     * Springwolf API endpoints that the Angular UI requests under /springwolf-ui/
     * but are actually served under /springwolf/.
     */
    private static final List<String> SPRINGWOLF_API_PATHS = List.of("/docs", "/ui-config");

   /**
    * Registers the {@link UiResourcesFilter} to handle all incoming requests ({@code /*}).
    * The filter intercepts Springwolf UI requests and serves the appropriate
    * static resources from the classpath.
    *
    * @return a {@link FilterRegistrationBean} configured with the UI resources filter
    */
   @Bean
   public FilterRegistrationBean<UiResourcesFilter> uiResourcesFilterRegistration() {
      System.out.println("SwaggerUiConfig: Registering UiResourcesFilter with pattern /*");
      FilterRegistrationBean<UiResourcesFilter> registration = new FilterRegistrationBean<>();
      registration.setFilter(new UiResourcesFilter());
      registration.addUrlPatterns("/*");
      registration.setOrder(0);
      return registration;
   }

   /**
    * Servlet filter that intercepts requests for Springwolf UI resources
    * and serves them from the classpath.
    * <p>
    * Requests matching the {@code /springwolf-ui} prefix are handled by this filter.
    * All other requests are passed through the filter chain.
    * </p>
    */
   public static class UiResourcesFilter implements Filter {

      private static final Logger log = LoggerFactory.getLogger(UiResourcesFilter.class);

      /**
       * Set of static resource file paths required by Springwolf UI.
       */
      private static final Set<String> SPRINGWOLF_UI_RESOURCES = Set.of(
            "/asyncapi-ui.html",
            "/styles-2J4TNLOB.css",
            "/main-6CAHIZNX.js",
            "/chunk-KX354HZD.js",
            "/chunk-6Y76BSYC.js",
            "/prerendered-routes.json",
            "/3rdpartylicenses.txt"
      );

      /**
       * Spring resource handler for Springwolf UI static resources.
       */
      private final ResourceHttpRequestHandler springwolfHandler;

      /**
       * Constructs the filter and initializes the Springwolf resource handler.
       *
       * @throws RuntimeException if a resource handler fails to initialize
       */
      public UiResourcesFilter() {
         System.out.println("UiResourcesFilter: Constructor called");
         log.info("UiResourcesFilter: Constructor called");

         // Initialize Springwolf UI handler
         this.springwolfHandler = new ResourceHttpRequestHandler();
         this.springwolfHandler.setLocations(List.of(new ClassPathResource(SPRINGWOLF_UI_CLASSPATH)));
         this.springwolfHandler.setResourceResolvers(List.of(new PathResourceResolver()));
         try {
            this.springwolfHandler.afterPropertiesSet();
         } catch (Exception e) {
            throw new RuntimeException("Failed to initialize SpringwolfUiResourceHttpRequestHandler", e);
         }
      }

      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
         HttpServletRequest request = (HttpServletRequest) servletRequest;
         HttpServletResponse response = (HttpServletResponse) servletResponse;
         String path = request.getRequestURI();

         log.debug("UiResourcesFilter: path={}", path);

          // Forward Springwolf API paths from /springwolf-ui/<endpoint> to /springwolf/<endpoint>
          // The Angular UI computes contextPath as /springwolf-ui/ (with trailing slash) and requests
          // /springwolf-ui//docs, /springwolf-ui//ui-config but Springwolf serves these at /springwolf/docs
          // Also handle single-slash variants like /springwolf-ui/docs
          if (path.startsWith("/springwolf-ui/")) {
             String suffix = path.substring("/springwolf-ui".length());
             // Normalize double slashes (from contextPath="/springwolf-ui/" + "/docs" = "/springwolf-ui//docs")
             suffix = suffix.replace("//", "/");

             // Check known API paths
             boolean isApiPath = false;
             for (String apiPath : SPRINGWOLF_API_PATHS) {
                if (suffix.equals(apiPath) || suffix.startsWith(apiPath + "/") || suffix.startsWith(apiPath + "?")) {
                   isApiPath = true;
                   break;
                }
             }
             // Handle publish endpoints: /{protocol}/publish or /{protocol}/publish/can
             if (!isApiPath && suffix.matches("/[^/]+/publish(/.*)?")) {
                isApiPath = true;
             }

             if (isApiPath) {
                String targetPath = "/springwolf" + suffix;
                log.debug("UiResourcesFilter: forwarding {} -> {}", path, targetPath);
                request.getRequestDispatcher(targetPath).forward(request, response);
                return;
             }
          }

         // Check for Springwolf UI resources
         if (isSpringwolfUiPath(path)) {
            handleSpringwolfUiRequest(request, response, path);
            return;
         }

         chain.doFilter(servletRequest, servletResponse);
      }

      private boolean isSpringwolfUiPath(String path) {
         return path.equals("/springwolf-ui") ||
               path.equals("/springwolf-ui/index.html") ||
               path.startsWith("/springwolf-ui/") || SPRINGWOLF_UI_RESOURCES.contains(path);
      }

      private void handleSpringwolfUiRequest(HttpServletRequest request, HttpServletResponse response, String path)
            throws IOException, ServletException {
         // Redirect to asyncapi-ui.html so the Angular app's getContextPath()
         // (which does pathname.split("/asyncapi-ui.html")[0]) computes "/springwolf-ui"
         // without a trailing slash, avoiding double-slash URLs like /springwolf-ui//docs
         if (path.equals("/springwolf-ui") || path.equals("/springwolf-ui/")) {
            response.sendRedirect(request.getContextPath() + "/springwolf-ui/asyncapi-ui.html");
            return;
         }
         String pathWithinHandlerMapping;
         if (path.equals("/springwolf-ui/index.html")) {
            pathWithinHandlerMapping = "asyncapi-ui.html";
         } else if (path.startsWith("/springwolf-ui/")) {
            pathWithinHandlerMapping = path.substring("/springwolf-ui/".length());
         } else {
            pathWithinHandlerMapping = path.substring(1);
         }
         log.debug("UiResourcesFilter: handling springwolf-ui pathWithinHandlerMapping={}", pathWithinHandlerMapping);
         request.setAttribute("org.springframework.web.servlet.HandlerMapping.pathWithinHandlerMapping", pathWithinHandlerMapping);
         request.setAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingHandler", springwolfHandler);
         request.setAttribute("org.springframework.web.servlet.HandlerMapping.lookupHandlerLookup", path);
         springwolfHandler.handleRequest(request, response);
      }
   }
}
