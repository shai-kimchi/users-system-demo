class MyConfig:
    def __init__(self, ):
        self.password_lenth = 10
        self.password_Regexp = ["((?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*\W))", "Password must contain Big letter, small letter, number and spical character"]
        self.password_num_of_history = 3
        self.password_dictionary = []
        self.passwordfile_to_set()
        self.login_attempted = 3

        # self.password_lenth = 1
        # self.password_Regexp = ["", "Password must contain Big letter, small letter, number and spical character"]
        # self.password_num_of_history = 3
        # self.password_dictionary = []
        # self.passwordfile_to_set()
        # self.login_attempted = 3

    def passwordfile_to_set(self):
        results = set()
        with open('most_common_passwords.txt', 'rt') as f:
            for line in f:
                self.password_dictionary.append((line.replace('\n', '')))
        return results
