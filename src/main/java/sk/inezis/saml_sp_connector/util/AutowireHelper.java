package sk.inezis.saml_sp_connector.util;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

public class AutowireHelper implements ApplicationContextAware {
    private static final AutowireHelper INSTANCE = new AutowireHelper();
    private static ApplicationContext applicationContext;

    private AutowireHelper() {
    }

    public static void autowire(Object clazz, Object bean) {
        if (bean == null) {
            applicationContext.getAutowireCapableBeanFactory().autowireBean(clazz);
        }
    }

    @Override
    public void setApplicationContext(final ApplicationContext applicationContext) {
        AutowireHelper.applicationContext = applicationContext;
    }

    public static AutowireHelper getInstance() {
        return INSTANCE;
    }
}
