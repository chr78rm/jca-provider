/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.christofreichardt.crypto;

import de.christofreichardt.crypto.schnorrsignature.SchnorrGroupsUnit;
import de.christofreichardt.crypto.schnorrsignature.SchnorrKeyGeneratorUnit;
import de.christofreichardt.crypto.schnorrsignature.SignatureUnit;
import de.christofreichardt.junit.MySuite;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 *
 * @author Developer
 */
@RunWith(MySuite.class)
@Suite.SuiteClasses({
  ExperimentalUnit.class,
  SchnorrKeyGeneratorUnit.class,
  SchnorrGroupsUnit.class,
  SignatureUnit.class
})
public class SchnorrSignatureSuite {
}
