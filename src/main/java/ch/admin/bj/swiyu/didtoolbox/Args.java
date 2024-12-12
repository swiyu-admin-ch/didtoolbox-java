package ch.admin.bj.swiyu.didtoolbox;

import com.beust.jcommander.Parameter;

import java.util.ArrayList;
import java.util.List;

public class Args {
    @Parameter
    private List<String> parameters = new ArrayList<>();

    @Parameter(names = { "-log", "-verbose" }, description = "Level of verbosity")
    private Integer verbose = 1;

    @Parameter(names = "-groups", description = "Comma-separated list of group names to be run")
    private String groups;

    @Parameter(names = "-debug", description = "Debug mode")
    private boolean debug = false;

    private Integer setterParameter;
    @Parameter(names = "-setterParameter", description = "A parameter annotation on a setter method")
    public void setParameter(Integer value) {
        this.setterParameter = value;
    }
}
