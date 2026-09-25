package top.ddupan.iam.login;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@Import(TestcontainersConfiguration.class)
@SpringBootTest
class IamLoginApplicationTests {

	@Test
	void contextLoads() {
	}

}
