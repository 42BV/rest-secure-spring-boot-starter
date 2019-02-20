package nl._42.restsecure.autoconfigure.authentication;

import nl._42.restsecure.autoconfigure.authentication.RegisteredUser;
import nl._42.restsecure.autoconfigure.authentication.UserDetailsAdapter;
import nl._42.restsecure.autoconfigure.authentication.WithUser;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.List;

import static java.util.stream.Collectors.toList;

public final class WithUserSecurityContextFactory implements
        WithSecurityContextFactory<WithUser>, BeanFactoryAware {

    private BeanFactory beanFactory;

    /**
     * Reads the expression resulting in a {@link nl._42.restsecure.autoconfigure.authentication.RegisteredUser}
     * and sets the user as authenticated in the SecurityContext
     *
     * @param withUser withUser annotation
     * @return SecurityContext to set
     */
    public SecurityContext createSecurityContext(WithUser withUser) {
        String userExpression = withUser.value();
        RegisteredUser registeredUser = evaluateExpression(userExpression);

        List<GrantedAuthority> authorityList = buildAuthorities(registeredUser);

        Authentication token = new UsernamePasswordAuthenticationToken(
                new UserDetailsAdapter<RegisteredUser>(registeredUser),
                null,
                authorityList
        );
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(token);
        return securityContext;
    }

    private List<GrantedAuthority> buildAuthorities(RegisteredUser registeredUser) {
        return registeredUser.getAuthorities()
                .stream()
                .map(a -> new SimpleGrantedAuthority(a))
                .collect(toList());
    }

    /**
     *
     * @param userExpression expression to evaluate to a RegisteredUser
     * @return RegisteredUser instance
     */
    private RegisteredUser evaluateExpression(String userExpression) {
        ExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setBeanResolver(new BeanFactoryResolver(this.beanFactory));

        Expression expression = parser.parseExpression(userExpression);
        return expression.getValue(context, RegisteredUser.class);
    }

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }
}