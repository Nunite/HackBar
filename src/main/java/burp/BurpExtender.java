/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

/**
 *
 * @author abdul.wahab
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    
    public String ExtensionName =  "Hack Bar";
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public IContextMenuInvocation context;
    public ArrayList menu_list;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.menu_list = new ArrayList();
        
        
        this.callbacks.setExtensionName(this.ExtensionName);
        this.callbacks.registerContextMenuFactory(this);
    }

    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.context = invocation;
        
        // 清空菜单列表
        menu_list.clear();
        
        // 直接添加各个功能菜单，而不是包装在主菜单中
        menu_list.add(new SQL_Menu(this));
        menu_list.add(new SQL_Error(this));
        menu_list.add(new SQli_LoginBypass(this));
        menu_list.add(new XSS_Menu(this));
        menu_list.add(new LFI_Menu(this));
        menu_list.add(new XXE_Menu(this));
        menu_list.add(new WebShell_Menu(this));
        menu_list.add(new Reverse_Shell_Menu(this));
        menu_list.add(new CustomStatement_Menu(this));
        
        return menu_list;
    }

    
}
