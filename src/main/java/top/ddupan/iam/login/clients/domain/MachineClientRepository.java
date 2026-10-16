package top.ddupan.iam.login.clients.domain;

import java.util.List;

/** Machine client persistence; they hold no secret, so nothing here is returned only once. */
public interface MachineClientRepository {
    List<MachineClient> listMachines(int page, int size);
    MachineClient getMachine(String id);
    MachineClient createMachine(MachineClient client);
    MachineClient updateMachine(MachineClient client);
    void deleteMachine(String id);
}
