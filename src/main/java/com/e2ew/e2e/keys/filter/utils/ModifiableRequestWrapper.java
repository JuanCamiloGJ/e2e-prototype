package com.e2ew.e2e.keys.filter.utils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

public class ModifiableRequestWrapper extends HttpServletRequestWrapper {
    private byte[] body;
    private final Map<String, String> headerOverrides = new ConcurrentHashMap<>();

    public ModifiableRequestWrapper(HttpServletRequest request) throws IOException {
        super(request);
        // cachear el body completo
        this.body = request.getInputStream().readAllBytes();
        // inicializar overrides con el content-type original para permitir cambios posteriores
        String ct = request.getContentType();
        if (ct != null) headerOverrides.put("content-type", ct);
    }

    /**
     * Devuelve los bytes crudos actuales del body
     */
    public byte[] getBody() {
        return body == null ? new byte[0] : body;
    }

    /**
     * Reemplaza el body por nuevos bytes
     */
    public void setBody(byte[] newBody) {
        this.body = (newBody != null) ? newBody : new byte[0];
    }

    /**
     * Sobrescribe o elimina un header (value==null elimina override)
     */
    public void setHeader(String name, String value) {
        if (name == null) return;
        String key = name.toLowerCase(Locale.ROOT);
        if (value == null) headerOverrides.remove(key);
        else headerOverrides.put(key, value);
    }

    /**
     * Cambia el content-type reportado
     */
    public void setContentType(String ct) {
        setHeader("Content-Type", ct);
    }

    @Override
    public String getContentType() {
        String overridden = headerOverrides.get("content-type");
        if (overridden != null) return overridden;
        return super.getContentType();
    }

    @Override
    public String getHeader(String name) {
        if (name == null) return null;
        String overridden = headerOverrides.get(name.toLowerCase(Locale.ROOT));
        if (overridden != null) return overridden;
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        if (name == null) return super.getHeaders(name);
        String overridden = headerOverrides.get(name.toLowerCase(Locale.ROOT));
        if (overridden != null) {
            return Collections.enumeration(Collections.singletonList(overridden));
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        Enumeration<String> original = super.getHeaderNames();
        Set<String> names = new LinkedHashSet<>();
        if (original != null) {
            while (original.hasMoreElements()) names.add(original.nextElement());
        }
        // agregar/actualizar nombres de headers sobreescritos
        names.addAll(headerOverrides.keySet());
        return Collections.enumeration(names);
    }

    @Override
    public int getContentLength() {
        return getBody().length;
    }

    @Override
    public long getContentLengthLong() {
        return getBody().length;
    }

    @Override
    public ServletInputStream getInputStream() {
        final ByteArrayInputStream bais = new ByteArrayInputStream(getBody());
        return new ServletInputStream() {
            @Override
            public int read() {
                return bais.read();
            }

            @Override
            public boolean isFinished() {
                return bais.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // no-op
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        Charset cs = StandardCharsets.UTF_8;
        String enc = getCharacterEncoding();
        if (enc != null) {
            try {
                cs = Charset.forName(enc);
            } catch (Exception e) {
                // Si el charset no es soportado, usar UTF-8 por defecto (ya asignado)
            }
        }
        return new BufferedReader(new InputStreamReader(getInputStream(), cs));
    }
}
