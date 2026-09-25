package top.ddupan.iam.login;

import org.springframework.boot.SpringApplication;

public class TestIamLoginApplication {

	public static void main(String[] args) {
		SpringApplication.from(IamLoginApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
