package com.e2ew.e2e.keys.utils;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.e2ew.e2e.keys.security.annotations.EncryptField;

public final class AccessPlans {
    private static AccessPlan getInnerObject(Object type) {
        Class<?> clazz = type.getClass();
        MethodHandle envGetter = null;
        Field envField = null;
        Object inner = null;
        // Envelope por convención "responseBody"
        try {
            var m = clazz.getMethod("getResponseBody");
            envGetter = MethodHandles.lookup().unreflect(m);
            inner = envGetter.invoke(type);
        } catch (Throwable ignore) {
            // probar campo
            Field f = findField(clazz, "responseBody");
            if (f != null) {
                try {
                    // Intentar la API recomendada
                    if (f.trySetAccessible()) {
                        envField = f;
                        inner = envField.get(type);

                    } else {
                        // Si no se permite cambiar accesibilidad, obtener un MethodHandle privado
                        var privLookup = MethodHandles.privateLookupIn(clazz, MethodHandles.lookup());
                        envGetter = privLookup.unreflectGetter(f);
                        inner = envGetter.invoke(type);
                    }
                } catch (Throwable ignoreField) {
                    // en entornos restrictivos puede fallar; continuar sin lanzar
                }
            }
        }

        var finalObject = Objects.requireNonNullElse(inner, type);
        return new AccessPlan(finalObject, finalObject.getClass(), getSensitiveFields(finalObject), inner != null);

    }

    private static Set<String> getSensitiveFields(Object type) {
        Set<String> sens = new HashSet<>();
        if (type != null) {
            for (Field f : getAllFields(type.getClass())) {
                if (f.isAnnotationPresent(EncryptField.class)) {
                    sens.add(f.getName());
                }
            }
        }
        return sens;
    }

    /**
     * Obtiene el plan de acceso para un tipo dado, cargando el objeto interior si es un envelope
     *
     * @param type Objeto a inspeccionar
     * @return Plan de acceso
     */
    public static AccessPlan planFor(Object type) {
        return getInnerObject(type); // forzar carga de inner
    }

    private static Field findField(Class<?> t, String name) {
        while (t != null && t != Object.class) {
            try {
                return t.getDeclaredField(name);
            } catch (NoSuchFieldException ignore) {
            }
            t = t.getSuperclass();
        }
        return null;
    }

    private static List<Field> getAllFields(Class<?> t) {
        List<Field> out = new ArrayList<>();
        while (t != null && t != Object.class) {
            out.addAll(Arrays.asList(t.getDeclaredFields()));
            t = t.getSuperclass();
        }
        return out;
    }

    public record AccessPlan(
            Object innerObject,       // objeto interior (o el mismo si no hay envelope)
            Class<?> clazz,
            Set<String> encryptFieldNames,
            boolean isEnvelope
    ) {
    }
}
